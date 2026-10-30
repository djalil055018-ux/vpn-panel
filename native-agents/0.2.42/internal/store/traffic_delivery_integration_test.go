//go:build integration

package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestDurableTrafficDeliveryIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(60*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("clone connection failed")
	}
	defer p.Close()
	var database string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "CODEX-TRAFFIC-DELIVERY")
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
	node, err := p.CreateNode(ctx, tenant.ID, "CODEX-DELIVERY-NODE", security.HashToken("fixture-node-bootstrap"))
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "CODEX-DELIVERY-CLIENT", nil)
	check(err)
	_, err = p.SetVPNClientLimits(ctx, client.ID, 280, 0)
	check(err)
	check(p.SaveHealth(ctx, node.ID, model.HealthReport{CheckedAt: time.Now().Add(-time.Hour), Healthy: false}))
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET last_seen_at=now()-interval '1 hour' WHERE id=$1::uuid`, node.ID)
	check(err)
	now := time.Now().UTC()
	previous := trafficPeriod(now).Add(-time.Minute)
	a, b := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	makeDelivery := func(seq, up int64, epoch string, at time.Time) model.TrafficDelivery {
		return model.TrafficDelivery{RecordedAt: at, Snapshot: model.ClientTrafficSnapshot{Sequence: seq, Epoch: epoch, Clients: []model.ClientTraffic{{ClientID: client.ID, Uplink: up, ActiveIPs: 2}}}}
	}
	for _, test := range []struct {
		seq, up, total int64
		epoch          string
		at             time.Time
		active         int
	}{
		{1, 100, 0, a, previous, 0}, {2, 150, 50, a, now.Add(-5 * time.Minute), 0}, {3, 170, 70, a, now, 2}, {4, 200, 270, b, now, 2},
	} {
		check(p.SaveTrafficDelivery(ctx, node.ID, makeDelivery(test.seq, test.up, test.epoch, test.at)))
		usage, err := p.VPNClientUsage(ctx, client.ID)
		check(err)
		if usage.UsedBytes != test.total || (usage.ActiveIPs == nil || *usage.ActiveIPs != test.active) {
			t.Fatalf("delivery %d total=%d active=%v", test.seq, usage.UsedBytes, usage.ActiveIPs)
		}
	}
	var healthy, fresh bool
	var applied int64
	check(p.Pool.QueryRow(ctx, `SELECT h.healthy,n.last_seen_at>now()-interval '2 minutes',n.applied_generation FROM nodes n JOIN node_health h ON h.node_id=n.id WHERE n.id=$1::uuid`, node.ID).Scan(&healthy, &fresh, &applied))
	if healthy || fresh || applied != 0 {
		t.Fatal("traffic replay overwrote runtime health or liveness")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE node_client_traffic_cursors SET observed_at=now()-interval '5 minutes' WHERE node_id=$1::uuid`, node.ID)
	check(err)
	check(p.SaveTrafficDelivery(ctx, node.ID, makeDelivery(3, 170, a, now)))
	check(p.SaveTrafficDelivery(ctx, node.ID, makeDelivery(4, 200, b, now)))
	usage, err := p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 270 || (usage.ActiveIPs == nil || *usage.ActiveIPs != 0) {
		t.Fatal("replay charged or refreshed an old observation")
	}
	check(p.SaveTrafficDelivery(ctx, node.ID, makeDelivery(5, 220, b, now)))
	usage, err = p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 290 || !usage.QuotaExceeded {
		t.Fatal("queued traffic failed quota enforcement")
	}
	// A rolled-back old agent's inline traffic cannot bypass the disk queue.
	check(p.SaveHealth(ctx, node.ID, model.HealthReport{Healthy: true, CheckedAt: now, TrafficSnapshot: &model.ClientTrafficSnapshot{Sequence: 999, Epoch: a, Clients: []model.ClientTraffic{{ClientID: client.ID, Uplink: 9000}}}}))
	usage, err = p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 290 {
		t.Fatal("old inline report bypassed dedicated delivery mode")
	}
	var previousBytes int64
	check(p.Pool.QueryRow(ctx, `SELECT uplink_bytes FROM vpn_client_usage_monthly WHERE client_id=$1::uuid AND period_start=$2::date`, client.ID, trafficPeriod(previous)).Scan(&previousBytes))
	if previousBytes != 100 {
		t.Fatal("delayed month boundary bytes misattributed")
	}
	if err = p.SaveTrafficDelivery(ctx, node.ID, makeDelivery(6, 300, b, now.Add(time.Hour))); err == nil {
		t.Fatal("future traffic timestamp accepted")
	}
}
