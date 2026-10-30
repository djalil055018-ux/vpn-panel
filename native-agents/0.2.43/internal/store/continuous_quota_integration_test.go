//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
)

func TestRemnawaveContinuousQuotaPreparationIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, e := p.CreateTenant(ctx, "Continuous held source")
	check(e)
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	check(e)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	inv["captured_at"] = "2026-09-25T21:00:02.123456789Z"
	for _, v := range inv["users"].([]any) {
		v.(map[string]any)["trafficLimitStrategy"] = "NO_RESET"
	}
	raw, e = json.Marshal(inv)
	check(e)
	_, report, e := remnawave.Parse(raw)
	check(e)
	staged, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(e)
	if _, e = p.PrepareRemnawaveNoResetQuota(ctx, staged.ID, tenant.ID, strings.Repeat("0", 64)); !errors.Is(e, ErrRemnawaveReview) {
		t.Fatal("wrong reviewed digest accepted")
	}
	for _, restricted := range []context.Context{WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}}), WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})} {
		if _, e = p.PrepareRemnawaveNoResetQuota(restricted, staged.ID, tenant.ID, report.SHA256); !errors.Is(e, ErrNotFound) {
			t.Fatal("non-owner prepared import")
		}
	}
	first, e := p.PrepareRemnawaveNoResetQuota(ctx, staged.ID, tenant.ID, report.SHA256)
	check(e)
	if first.Prepared != 3 || first.CutoverReady {
		t.Fatal("held preparation count or cutover flag")
	}
	again, e := p.PrepareRemnawaveNoResetQuota(ctx, staged.ID, tenant.ID, report.SHA256)
	check(e)
	if again.Prepared != 0 || again.Existing != 3 {
		t.Fatal("baseline replay was not idempotent")
	}
	clients, e := p.ListVPNClients(ctx, tenant.ID)
	check(e)
	for _, c := range clients {
		if c.Status != "disabled" || !c.RemnawaveHold {
			t.Fatal("quota preparation released hold")
		}
	}
	mappings, e := p.RemnawaveImportClients(ctx, staged.ID, 0, 250)
	check(e)
	usage, e := p.VPNClientUsage(ctx, mappings[0].ClientID)
	check(e)
	if usage.ResetPolicy != "NO_RESET" || usage.ImportedBytes != 123456 || usage.UsedBytes != 123456 || usage.UplinkBytes != 0 || usage.DownlinkBytes != 0 || usage.MonthlyLimitBytes != 0 || usage.TrafficLimitBytes != 1000000000 {
		t.Fatal("source used bytes, directions or limit were rewritten")
	}
	var kept []byte
	check(p.Pool.QueryRow(ctx, `SELECT inventory FROM remnawave_imports WHERE id=$1::uuid`, staged.ID).Scan(&kept))
	if !bytes.Equal(raw, kept) {
		t.Fatal("immutable source changed")
	}
	var grants int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_services WHERE tenant_id=$1::uuid`, tenant.ID).Scan(&grants))
	if grants != 0 {
		t.Fatal("preparation granted access")
	}
	_, e = p.DeleteVPNClient(ctx, mappings[0].ClientID, mappings[0].Name)
	check(e)
	afterDelete, e := p.PrepareRemnawaveNoResetQuota(ctx, staged.ID, tenant.ID, report.SHA256)
	check(e)
	if afterDelete.Deleted != 1 || afterDelete.Existing != 2 || afterDelete.Prepared != 0 {
		t.Fatal("deleted source client resurrected")
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_continuous_quotas WHERE client_id=$1::uuid`, mappings[0].ClientID).Scan(&count))
	if count != 0 {
		t.Fatal("delete retained live accounting row")
	}
	// Conflicting repeat cannot reset an operator edit or any target usage.
	_, e = p.SetVPNClientContinuousLimit(ctx, mappings[1].ClientID, 10)
	check(e)
	if _, e = p.PrepareRemnawaveNoResetQuota(ctx, staged.ID, tenant.ID, report.SHA256); !errors.Is(e, ErrRemnawaveConflict) {
		t.Fatal("repeat overwrote edited limit")
	}
}

func TestContinuousQuotaAccessAndAccountingIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, services := nativeAccessFixture(t, ctx, p)
	service := services[0]
	var node, otherNode string
	check(p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, service).Scan(&node))
	check(p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, services[1]).Scan(&otherNode))
	client, e := p.CreateVPNClient(ctx, tenant, "Continuous synthetic", nil)
	check(e)
	_, e = p.Pool.Exec(ctx, `INSERT INTO vpn_client_continuous_quotas(client_id,limit_bytes,baseline_bytes,baseline_at) VALUES($1::uuid,150,80,now()-interval '40 days')`, client.ID)
	check(e)
	_, e = p.AttachVPNClientAndRebuild(ctx, service, client.ID)
	check(e)
	_, e = p.CreateVPNClientSubscription(ctx, client.ID, bytes.Repeat([]byte{1}, 16), 1, bytes.Repeat([]byte{2}, 32), "synthetic-continuous")
	check(e)
	assertAccess := func(want bool) {
		t.Helper()
		connections, e := p.ListVPNClientConnections(ctx, client.ID)
		check(e)
		if (len(connections) == 1) != want {
			t.Fatal("connections ignored continuous quota")
		}
		var count int
		check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN desired_states d ON d.node_id=n.id AND d.generation=n.desired_generation,jsonb_array_elements(d.document->'services') s,jsonb_array_elements(s->'clients') c WHERE n.id=$1::uuid AND c->>'id'=$2`, node, client.VLESSUUID).Scan(&count))
		if (count == 1) != want {
			t.Fatal("desired state ignored continuous quota")
		}
	}
	assertAccess(true)
	now := time.Now().UTC()
	epochA := strings.Repeat("a", 32)
	epochB := strings.Repeat("b", 32)
	delivery := func(n string, seq, up int64, epoch string, at time.Time) error {
		return p.SaveTrafficDelivery(ctx, n, model.TrafficDelivery{RecordedAt: at, Snapshot: model.ClientTrafficSnapshot{Sequence: seq, Epoch: epoch, Clients: []model.ClientTraffic{{ClientID: client.ID, Uplink: up}}}})
	}
	for _, v := range []struct {
		seq, up, total int64
		epoch          string
		at             time.Time
	}{{1, 20, 100, epochA, trafficPeriod(now).Add(-time.Minute)}, {2, 40, 120, epochA, now}, {3, 80, 160, epochA, now}, {3, 80, 160, epochA, now}, {2, 40, 160, epochA, now}, {4, 5, 165, epochB, now}} {
		check(delivery(node, v.seq, v.up, v.epoch, v.at))
		usage, e := p.VPNClientUsage(ctx, client.ID)
		check(e)
		if usage.UsedBytes != v.total || usage.ImportedBytes != 80 {
			t.Fatalf("continuous delivery seq%d: used=%d", v.seq, usage.UsedBytes)
		}
		assertAccess(v.total < 150)
	}
	// Current-month rows are irrelevant to NO_RESET, including monthly unlimited.
	_, e = p.Pool.Exec(ctx, `DELETE FROM vpn_client_usage_monthly WHERE client_id=$1::uuid AND period_start=date_trunc('month',now() AT TIME ZONE 'UTC')::date`, client.ID)
	check(e)
	_, e = p.ReconcileInactiveVPNClients(ctx)
	check(e)
	assertAccess(false)
	if _, e = p.SetVPNClientLimits(ctx, client.ID, 0, 0); !errors.Is(e, ErrTrafficPolicyConflict) {
		t.Fatal("legacy monthly writer changed no-reset policy")
	}
	wrong := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Role: "operator"})
	if _, e = p.SetVPNClientContinuousLimit(wrong, client.ID, 0); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant limit write")
	}
	if _, e = p.VPNClientUsage(wrong, client.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant usage read")
	}
	check(delivery(otherNode, 1, 7, epochA, now))
	usage, e := p.VPNClientUsage(ctx, client.ID)
	check(e)
	if usage.UsedBytes != 172 {
		t.Fatal("second node traffic was not added")
	}
	_, e = p.SetVPNClientContinuousLimit(ctx, client.ID, 0)
	check(e)
	assertAccess(true)
	_, e = p.Pool.Exec(ctx, `INSERT INTO vpn_client_limits(client_id,monthly_bytes) VALUES($1::uuid,1)`, client.ID)
	check(e)
	_, e = p.Pool.Exec(ctx, `INSERT INTO vpn_client_usage_monthly(client_id,period_start,uplink_bytes,downlink_bytes) VALUES($1::uuid,date_trunc('month',now() AT TIME ZONE 'UTC')::date,999,0) ON CONFLICT(client_id,period_start) DO UPDATE SET uplink_bytes=999`, client.ID)
	check(e)
	_, e = p.ReconcileInactiveVPNClients(ctx)
	check(e)
	assertAccess(true)
	_, e = p.SetVPNClientContinuousLimit(ctx, client.ID, 200)
	check(e)
	// A desired-state failure must roll back the charge, cursor and quota denial.
	_, e = p.Pool.Exec(ctx, `CREATE FUNCTION reject_quota_desired() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic desired failure'; END $$; CREATE TRIGGER reject_quota_desired BEFORE INSERT ON desired_states FOR EACH ROW EXECUTE FUNCTION reject_quota_desired()`)
	check(e)
	if e = delivery(node, 5, 100, epochB, now); e == nil {
		t.Fatal("injected desired failure ignored")
	}
	usage, e = p.VPNClientUsage(ctx, client.ID)
	check(e)
	if usage.UsedBytes != 172 || usage.QuotaExceeded {
		t.Fatal("failed rebuild committed accounting")
	}
	assertAccess(true)
	_, e = p.Pool.Exec(ctx, `DROP TRIGGER reject_quota_desired ON desired_states; DROP FUNCTION reject_quota_desired()`)
	check(e)
	check(delivery(node, 5, 100, epochB, now))
	usage, e = p.VPNClientUsage(ctx, client.ID)
	check(e)
	if usage.UsedBytes != 267 {
		t.Fatal("retried delivery lost or doubled charge")
	}
	assertAccess(false)
	current, e := p.GetVPNClient(ctx, client.ID)
	check(e)
	if current.EffectiveStatus != "quota_exceeded" {
		t.Fatal("client effective status omitted no-reset quota")
	}
	_, e = p.SetVPNClientContinuousLimit(ctx, client.ID, 1000)
	check(e)
	assertAccess(true)
	_, e = p.SetVPNClientStatus(ctx, client.ID, "disabled")
	check(e)
	assertAccess(false)
	_, e = p.SetVPNClientStatus(ctx, client.ID, "active")
	check(e)
	assertAccess(true)
	expired := now.Add(-time.Minute)
	_, e = p.UpdateVPNClient(ctx, client.ID, nil, nil, &expired, true)
	check(e)
	assertAccess(false)
}
