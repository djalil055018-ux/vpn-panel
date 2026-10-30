//go:build integration

package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestTrafficRuntimeEpochAndReplayIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(60*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
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
	const tenant = "68e8e76d-3f16-4ad0-8e91-8a4888a1ad80"
	const node = "50a85540-9f2c-4aa1-ba50-bc8c4267877d"
	c, err := p.CreateVPNClient(ctx, tenant, "CODEX-ORDERED-TRAFFIC", nil)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM vpn_clients WHERE id=$1::uuid`, c.ID)
	const a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const d = "cccccccccccccccccccccccccccccccc"
	for _, tc := range []struct {
		epoch                string
		seq, up, down, total int64
	}{
		{"", 0, 100, 50, 150}, {a, 10, 100, 50, 150}, {a, 11, 120, 60, 180}, {a, 10, 100, 50, 180},
		{b, 12, 200, 100, 480}, {a, 11, 120, 60, 480}, {b, 13, 5, 1, 480},
		{b, 14, 220, 110, 510}, {"", 0, 2000, 2000, 510}, {d, 15, 10, 5, 525},
	} {
		samples := []model.ClientTraffic{{ClientID: c.ID, Uplink: tc.up, Downlink: tc.down, ActiveIPs: 3}}
		report := model.HealthReport{Healthy: true, CheckedAt: time.Now()}
		if tc.epoch == "" {
			report.ClientTraffic = samples
		} else {
			report.TrafficSnapshot = &model.ClientTrafficSnapshot{Epoch: tc.epoch, Sequence: tc.seq, Clients: samples}
		}
		check(p.SaveHealth(ctx, node, report))
		usage, err := p.VPNClientUsage(ctx, c.ID)
		check(err)
		if usage.UsedBytes != tc.total {
			t.Fatalf("sequence %d usage=%d want=%d", tc.seq, usage.UsedBytes, tc.total)
		}
	}
	_, err = p.Pool.Exec(ctx, `UPDATE node_client_traffic_cursors SET observed_at=now()-interval '3 minutes' WHERE node_id=$1::uuid AND client_id=$2::uuid`, node, c.ID)
	check(err)
	check(p.SaveHealth(ctx, node, model.HealthReport{Healthy: true, CheckedAt: time.Now(), TrafficSnapshot: &model.ClientTrafficSnapshot{Epoch: d, Sequence: 15, Clients: []model.ClientTraffic{{ClientID: c.ID, Uplink: 10, Downlink: 5, ActiveIPs: 3}}}}))
	usage, err := p.VPNClientUsage(ctx, c.ID)
	check(err)
	if usage.ActiveIPs == nil || *usage.ActiveIPs != 0 {
		t.Fatal("replayed sample refreshed obsolete online addresses")
	}
}
