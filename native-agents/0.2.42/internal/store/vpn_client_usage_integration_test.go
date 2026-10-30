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

func TestVPNClientTrafficQuotaIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(90*time.Second))
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
	const service = "45851736-7be9-43f2-bae2-725822b35bfa"
	var node string
	check(p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, service).Scan(&node))
	client, err := p.CreateVPNClient(ctx, tenant, "CODEX-TRAFFIC-INTEGRATION", nil)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM vpn_clients WHERE id=$1::uuid`, client.ID)
	_, err = p.AttachVPNClientAndRebuild(ctx, service, client.ID)
	check(err)
	usage, err := p.SetVPNClientLimits(ctx, client.ID, 150, 2)
	check(err)
	if usage.QuotaExceeded || usage.UsedBytes != 0 || (usage.ActiveIPs == nil || *usage.ActiveIPs != 0) || usage.DeviceWarning {
		t.Fatal("new limit started exceeded")
	}
	report := model.HealthReport{Healthy: true, CheckedAt: time.Now().UTC(), ClientTraffic: []model.ClientTraffic{{ClientID: client.ID, Uplink: 100, Downlink: 30, ActiveIPs: 3}}}
	check(p.SaveHealth(ctx, node, report))
	usage, err = p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 130 || usage.QuotaExceeded || !usage.DeviceWarning || (usage.ActiveIPs == nil || *usage.ActiveIPs != 3) {
		t.Fatalf("unexpected first usage: %+v", usage)
	}
	check(p.SaveHealth(ctx, node, report))
	usage, err = p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 130 {
		t.Fatal("repeated cumulative counter was double counted")
	}
	report.ClientTraffic[0].Uplink = 130
	report.ClientTraffic[0].Downlink = 40
	report.CheckedAt = time.Now().UTC()
	check(p.SaveHealth(ctx, node, report))
	usage, err = p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 170 || !usage.QuotaExceeded || usage.RemainingBytes != 0 {
		t.Fatalf("quota did not close: %+v", usage)
	}
	var desired int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation,jsonb_array_elements(ds.document->'services') service,jsonb_array_elements(service->'clients') member WHERE n.id=$1::uuid AND member->>'id'=$2`, node, client.VLESSUUID).Scan(&desired))
	if desired != 0 {
		t.Fatal("quota-exceeded client remained in desired state")
	}
	current, err := p.GetVPNClient(ctx, client.ID)
	check(err)
	if current.EffectiveStatus != "quota_exceeded" {
		t.Fatalf("effective status=%s", current.EffectiveStatus)
	}
	report.ClientTraffic[0].Uplink = 10
	report.ClientTraffic[0].Downlink = 5
	report.CheckedAt = time.Now().UTC()
	check(p.SaveHealth(ctx, node, report))
	usage, err = p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 185 {
		t.Fatalf("counter reset usage=%d", usage.UsedBytes)
	}
	_, err = p.SetVPNClientLimits(ctx, client.ID, 0, 2)
	check(err)
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation,jsonb_array_elements(ds.document->'services') service,jsonb_array_elements(service->'clients') member WHERE n.id=$1::uuid AND member->>'id'=$2`, node, client.VLESSUUID).Scan(&desired))
	if desired != 1 {
		t.Fatal("unlimited client was not restored")
	}
	// Reports for other clients must not erase an idle cumulative baseline.
	idle, err := p.CreateVPNClient(ctx, tenant, "CODEX-TRAFFIC-IDLE", nil)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM vpn_clients WHERE id=$1::uuid`, idle.ID)
	idleReport := model.HealthReport{Healthy: true, CheckedAt: time.Now(), ClientTraffic: []model.ClientTraffic{{ClientID: idle.ID, Uplink: 1000, Downlink: 2000}}}
	check(p.SaveHealth(ctx, node, idleReport))
	_, err = p.Pool.Exec(ctx, `UPDATE node_client_traffic_cursors SET observed_at=now()-interval '40 days' WHERE node_id=$1::uuid AND client_id=$2::uuid`, node, idle.ID)
	check(err)
	staleUsage, err := p.VPNClientUsage(ctx, idle.ID)
	check(err)
	if (staleUsage.ActiveIPs == nil || *staleUsage.ActiveIPs != 0) || staleUsage.DeviceWarning {
		t.Fatal("expired observations must contribute zero active addresses")
	}
	check(p.SaveHealth(ctx, node, report))
	check(p.SaveHealth(ctx, node, idleReport))
	idleUsage, err := p.VPNClientUsage(ctx, idle.ID)
	check(err)
	if idleUsage.UsedBytes != 3000 {
		t.Fatalf("idle cumulative traffic charged twice: %d", idleUsage.UsedBytes)
	}
	_, err = p.AttachVPNClientAndRebuild(ctx, service, idle.ID)
	check(err)
	_, err = p.SetVPNClientLimits(ctx, idle.ID, 2500, 0)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_client_usage_monthly SET period_start=(date_trunc('month',now() AT TIME ZONE 'UTC')-interval '1 month')::date WHERE client_id=$1::uuid`, idle.ID)
	check(err)
	_, err = p.ReconcileInactiveVPNClients(ctx)
	check(err)
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation,jsonb_array_elements(ds.document->'services') service,jsonb_array_elements(service->'clients') member WHERE n.id=$1::uuid AND member->>'id'=$2`, node, idle.VLESSUUID).Scan(&desired))
	if desired != 1 {
		t.Fatal("month rollover did not restore eligible client")
	}
	idleReport.ClientTraffic[0].Uplink += 10
	check(p.SaveHealth(ctx, node, idleReport))
	idleUsage, err = p.VPNClientUsage(ctx, idle.ID)
	check(err)
	if idleUsage.UsedBytes != 10 || idleUsage.QuotaExceeded {
		t.Fatal("month rollover counted the old cumulative baseline")
	}
	var otherNode string
	check(p.Pool.QueryRow(ctx, `SELECT id::text FROM nodes WHERE tenant_id=$1::uuid AND id<>$2::uuid ORDER BY id LIMIT 1`, tenant, node).Scan(&otherNode))
	idleReport.ClientTraffic[0].Uplink, idleReport.ClientTraffic[0].Downlink = 5, 7
	check(p.SaveHealth(ctx, otherNode, idleReport))
	idleUsage, err = p.VPNClientUsage(ctx, idle.ID)
	check(err)
	if idleUsage.UsedBytes != 22 {
		t.Fatal("traffic from multiple nodes was not aggregated")
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "viewer"})
	if _, err = p.VPNClientUsage(scoped, client.ID); err != nil {
		t.Fatal("tenant could not read owned usage")
	}
}
