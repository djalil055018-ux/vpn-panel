//go:build integration

package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestTrafficAddressAvailabilityIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
	tenant, err := p.CreateTenant(ctx, "CODEX-ADDRESS-AVAILABILITY")
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
	xray, err := p.CreateNode(ctx, tenant.ID, "CODEX-ADDRESS-XRAY", security.HashToken("fixture-bootstrap-xray"))
	check(err)
	hysteria, err := p.CreateNode(ctx, tenant.ID, "CODEX-ADDRESS-HYSTERIA", security.HashToken("fixture-bootstrap-hysteria"))
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "CODEX-ADDRESS-CLIENT", nil)
	check(err)
	_, err = p.SetVPNClientLimits(ctx, client.ID, 0, 1)
	check(err)
	now := time.Now().UTC()
	delivery := func(seq, up int64, count int, unavailable bool) model.TrafficDelivery {
		return model.TrafficDelivery{RecordedAt: now, Snapshot: model.ClientTrafficSnapshot{Sequence: seq, Epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Clients: []model.ClientTraffic{{ClientID: client.ID, Uplink: up, ActiveIPs: count, ActiveIPsUnavailable: unavailable}}}}
	}
	assertUsage := func(bytes int64, count *int, warning bool) {
		t.Helper()
		usage, err := p.VPNClientUsage(ctx, client.ID)
		check(err)
		if usage.UsedBytes != bytes || usage.DeviceWarning != warning || (usage.ActiveIPs == nil) != (count == nil) {
			t.Fatal("usage availability/bytes/warning mismatch")
		}
		if count != nil && *usage.ActiveIPs != *count {
			t.Fatal("measured address count mismatch")
		}
		raw, err := json.Marshal(usage)
		check(err)
		if count == nil && !strings.Contains(string(raw), `"active_ips":null`) {
			t.Fatal("API did not represent unknown as null")
		}
		operations, err := p.OperationsStatus(ctx)
		check(err)
		found := false
		for _, item := range operations.ClientDeviceWarnings {
			if item.ClientID == client.ID {
				found = true
			}
		}
		if found != warning {
			t.Fatal("operations warning differs from client telemetry availability")
		}
	}
	measured := 3
	check(p.SaveTrafficDelivery(ctx, xray.ID, delivery(1, 100, measured, false)))
	assertUsage(100, &measured, true)
	check(p.SaveTrafficDelivery(ctx, hysteria.ID, delivery(1, 200, 0, true)))
	assertUsage(300, nil, false)
	// Bytes keep accruing while addresses remain unknown. Replays may not make
	// old known telemetry replace a newer unknown observation.
	check(p.SaveTrafficDelivery(ctx, hysteria.ID, delivery(2, 250, 0, true)))
	check(p.SaveTrafficDelivery(ctx, hysteria.ID, delivery(1, 200, 2, false)))
	assertUsage(350, nil, false)
	// Contradictory unknown+positive telemetry rolls back the whole delivery.
	if p.SaveTrafficDelivery(ctx, hysteria.ID, delivery(3, 300, 2, true)) == nil {
		t.Fatal("database accepted contradictory telemetry")
	}
	assertUsage(350, nil, false)
	// A later explicitly measured zero is different from unavailable.
	check(p.SaveTrafficDelivery(ctx, hysteria.ID, delivery(3, 300, 0, false)))
	assertUsage(400, &measured, true)
	check(p.SaveTrafficDelivery(ctx, hysteria.ID, delivery(4, 310, 0, true)))
	_, err = p.Pool.Exec(ctx, `UPDATE node_client_traffic_cursors SET observed_at=now()-interval '5 minutes' WHERE node_id=$1::uuid`, hysteria.ID)
	check(err)
	assertUsage(410, &measured, true)
	// Delivery replay cannot make stale unknown data current again.
	check(p.SaveTrafficDelivery(ctx, hysteria.ID, delivery(4, 310, 0, true)))
	assertUsage(410, &measured, true)
}
