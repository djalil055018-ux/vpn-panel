//go:build integration

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestClientDirectoryActivityIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, e := p.CreateTenant(ctx, "Directory synthetic tenant")
	check(e)
	other, e := p.CreateTenant(ctx, "Other directory tenant")
	check(e)
	client, e := p.CreateVPNClient(ctx, tenant.ID, "Synthetic client", nil)
	check(e)
	_, e = p.CreateVPNClient(ctx, other.ID, "Private other tenant", nil)
	check(e)
	first, e := p.CreateNode(ctx, tenant.ID, "Netherlands", security.HashToken("synthetic-first-node"))
	check(e)
	second, e := p.CreateNode(ctx, tenant.ID, "Sweden", security.HashToken("synthetic-second-node"))
	check(e)
	_, e = p.Pool.Exec(ctx, `WITH plan AS (INSERT INTO vpn_access_plans(tenant_id,name,code) VALUES($1::uuid,'Основная','main') RETURNING id,tenant_id) INSERT INTO vpn_client_access_plans(tenant_id,client_id,plan_id) SELECT tenant_id,$2::uuid,id FROM plan`, tenant.ID, client.ID)
	check(e)
	read := func() *model.ClientDirectory {
		t.Helper()
		rows, e := p.ListVPNClients(ctx, tenant.ID)
		check(e)
		if len(rows) != 1 || rows[0].ID != client.ID || rows[0].Directory == nil {
			t.Fatal("directory crossed tenant boundary or missing")
		}
		return rows[0].Directory
	}
	m := read()
	if m.ConnectionState != "unknown" || m.FirstConnectedAt != nil || m.LastOnlineAt != nil || m.LastTrafficResetAt != nil || len(m.Groups) != 1 || m.Groups[0] != "Основная" {
		t.Fatal("new client metadata fabricated history or lost group")
	}
	now := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	send := func(node string, seq, up int64, ips int, unknown bool, at time.Time) {
		t.Helper()
		check(p.SaveTrafficDelivery(ctx, node, model.TrafficDelivery{RecordedAt: at, Snapshot: model.ClientTrafficSnapshot{Sequence: seq, Epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Clients: []model.ClientTraffic{{ClientID: client.ID, Uplink: up, ActiveIPs: ips, ActiveIPsUnavailable: unknown}}}}))
	}
	send(first.ID, 1, 0, 0, true, now)
	m = read()
	if m.FirstConnectedAt != nil || m.LastOnlineAt != nil || m.ConnectionState != "unknown" {
		t.Fatal("empty telemetry invented a connection")
	}
	connected := now.Add(time.Second)
	send(first.ID, 2, 100, 1, false, connected)
	m = read()
	if m.FirstConnectedAt == nil || !m.FirstConnectedAt.Value.Equal(connected) || m.LastOnlineAt == nil || !m.LastOnlineAt.Value.Equal(connected) || m.LastNodeName == nil || *m.LastNodeName != "Netherlands" || m.ConnectionState != "online" || m.LifetimeUsedBytes == nil || *m.LifetimeUsedBytes != 100 {
		t.Fatal("positive traffic metadata incorrect")
	}
	send(first.ID, 3, 100, 0, false, now.Add(2*time.Second))
	m = read()
	if !m.LastOnlineAt.Value.Equal(connected) || m.ConnectionState != "offline" {
		t.Fatal("zero telemetry moved last connection or failed explicit offline observation")
	}
	send(second.ID, 1, 0, 0, true, now.Add(3*time.Second))
	if read().ConnectionState != "unknown" {
		t.Fatal("unknown second node was represented as offline")
	}
	last := now.Add(4 * time.Second)
	send(second.ID, 2, 20, 0, true, last)
	m = read()
	if *m.LastNodeName != "Sweden" || !m.LastOnlineAt.Value.Equal(last) || !m.FirstConnectedAt.Value.Equal(connected) || m.ConnectionState != "unknown" || *m.LifetimeUsedBytes != 120 {
		t.Fatal("multi-node bytes or activity aggregate incorrect")
	}
	// Replaying an old positive observation must not refresh online state or
	// change first/last timestamps, counters, or most recent node.
	send(first.ID, 2, 100, 8, false, now.Add(5*time.Second))
	m = read()
	if m.ConnectionState != "unknown" || *m.LifetimeUsedBytes != 120 || *m.LastNodeName != "Sweden" || !m.LastOnlineAt.Value.Equal(last) {
		t.Fatal("replayed observation changed directory")
	}
	send(second.ID, 3, 20, 0, false, now.Add(6*time.Second))
	if read().ConnectionState != "offline" {
		t.Fatal("explicit zero failed to clear unknown")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE node_client_traffic_cursors SET observed_at=now()-interval '5 minutes' WHERE client_id=$1::uuid`, client.ID)
	check(e)
	if read().ConnectionState != "unknown" {
		t.Fatal("stale offline observation advertised as current")
	}
	// Lifetime traffic spans monthly buckets; a monthly reset does not erase it.
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_client_usage_monthly SET period_start=(date_trunc('month',now())-interval '1 month')::date WHERE client_id=$1::uuid`, client.ID)
	check(e)
	send(second.ID, 4, 30, 0, true, now.Add(7*time.Second))
	if *read().LifetimeUsedBytes != 130 {
		t.Fatal("lifetime bytes lost across monthly rollover")
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: other.ID, Role: "viewer"})
	if _, e = p.ListVPNClients(scoped, tenant.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("other tenant could access directory")
	}
}

func TestClientDirectorySourceSnapshotIntegration(t *testing.T) {
	f := newHeldDeltaFixture(t)
	next := advanceDelta(t, f.inv)
	next["nodes"] = []any{map[string]any{"uuid": "fixture-node", "name": "Netherlands"}}
	u := next["users"].([]any)[0].(map[string]any)
	u["telegramId"] = float64(123456789)
	u["tag"] = "friends"
	u["lastTrafficResetAt"] = nil
	traffic := u["userTraffic"].(map[string]any)
	traffic["firstConnectedAt"] = "2026-09-01T10:00:00Z"
	traffic["onlineAt"] = "2026-09-25T20:59:59Z"
	traffic["lastConnectedNodeUuid"] = "fixture-node"
	_, e := f.apply(t, next, f.sha)
	deltaCheck(t, e)
	clients, e := f.p.ListVPNClients(f.ctx, f.tenant)
	deltaCheck(t, e)
	if len(clients) != 3 {
		t.Fatal("source mapping count changed")
	}
	found := false
	for _, client := range clients {
		if !client.RemnawaveHold || client.Status != "disabled" {
			t.Fatal("directory read enabled held client")
		}
		m := client.Directory
		if m == nil || m.NumericID == nil || m.SourceObservedAt == nil {
			t.Fatal("source projection missing")
		}
		encoded, e := json.Marshal(m)
		deltaCheck(t, e)
		for _, secret := range []string{"synthetic-source-subscription", "synthetic-trojan", "synthetic-ss", client.VLESSUUID, "fixture-node"} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatal("private source material escaped metadata projection")
			}
		}
		if *m.NumericID == 1 {
			found = true
			if m.TelegramID == nil || *m.TelegramID != "123456789" || m.Tag == nil || *m.Tag != "friends" || m.LastNodeName == nil || *m.LastNodeName != "Netherlands" || m.ConnectionState != "unknown" || m.SourceStatus != "ACTIVE" || m.FirstConnectedAt == nil || m.LastOnlineAt == nil || m.LastTrafficResetAt == nil || m.LastTrafficResetAt.Value != nil || *m.LifetimeUsedBytes != 654321 || len(m.Groups) != 1 {
				t.Fatal("source display metadata incomplete")
			}
		}
	}
	if !found {
		t.Fatal("source numeric identity not represented")
	}
	var active int
	deltaCheck(t, f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM vpn_clients WHERE tenant_id=$1::uuid AND NOT remnawave_hold`, f.tenant).Scan(&active))
	if active != 0 {
		t.Fatal("read-only metadata changed activation")
	}
}
