//go:build integration

package store

import (
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

func TestCascadeGroupLifecycleIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(90*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	defer p.Close()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var db string
	check(p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db))
	if !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	tenant, services := nativeAccessFixture(t, ctx, p)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.34' WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	plan, err := p.CreateVPNAccessPlan(ctx, tenant, "Cascade group", "cascade-group", true)
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant, "Cascade member", nil)
	check(err)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	input := model.VPNCascadeInput{Name: "🇳🇱 → 🇷🇺 Cascade", PlanID: plan.ID, EntryServiceID: services[0], ExitServiceID: services[1], EntryPort: 9443, Enabled: true}
	created, err := p.PutVPNCascade(ctx, tenant, "", input)
	check(err)
	if !created.Changed || created.Cascade == nil || len(created.Rebuilds) != 2 {
		t.Fatal("cascade did not atomically rebuild both nodes")
	}
	cascade := *created.Cascade
	var ordinary int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_effective_client_services WHERE client_id=$1::uuid`, client.ID).Scan(&ordinary))
	if ordinary != 0 {
		t.Fatal("cascade granted ordinary connections")
	}
	state := func(node string) model.DesiredState {
		t.Helper()
		s, ok, e := p.LatestDesiredState(ctx, node)
		check(e)
		if !ok {
			t.Fatal("missing desired state")
		}
		return s
	}
	memberCount := func(want int) {
		t.Helper()
		s := state(cascade.EntryNodeID)
		if s.XrayCascades == nil || len(s.XrayCascades.Entries) != 1 || len(s.XrayCascades.Entries[0].Clients) != want {
			t.Fatalf("cascade member count differs from %d", want)
		}
		if len(s.Services[0].Clients) != 0 {
			t.Fatal("ordinary service access changed")
		}
	}
	memberCount(1)
	exit := state(cascade.ExitNodeID)
	if exit.XrayCascades == nil || len(exit.XrayCascades.Exits) != 1 {
		t.Fatal("exit transit missing")
	}
	transit := exit.XrayCascades.Exits[0].ClientID
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if len(connections) != 0 {
		t.Fatal("unapplied cascade published")
	}
	ready := func() {
		t.Helper()
		_, e := p.Pool.Exec(ctx, `UPDATE nodes SET applied_generation=desired_generation WHERE tenant_id=$1::uuid`, tenant)
		check(e)
		_, e = p.Pool.Exec(ctx, `UPDATE deployments SET status='healthy',completed_at=now(),applied_core_version=requested_core_version WHERE node_id IN (SELECT id FROM nodes WHERE tenant_id=$1::uuid)`, tenant)
		check(e)
	}
	ready()
	connections, err = p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if len(connections) != 1 || connections[0].Port != 9443 || connections[0].DisplayName() != input.Name || len(connections[0].ImportedProfile) == 0 {
		t.Fatal("separate named profile missing")
	}
	public, _ := json.Marshal(connections)
	if strings.Contains(string(public), transit) {
		t.Fatal("subscription exposed transit credential")
	}
	listed, err := p.ListVPNCascades(ctx, tenant)
	check(err)
	public, _ = json.Marshal(listed)
	if strings.Contains(string(public), transit) {
		t.Fatal("definition exposed transit credential")
	}

	// Public readiness and tenant isolation are evaluated on one current snapshot.
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET status='online' WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	view, err := p.VPNCascadeStatus(ctx, cascade.ID)
	check(err)
	if view.State != "active" || view.EntryAppliedGeneration != view.EntryDesiredGeneration {
		t.Fatal("ready status did not match applied state")
	}
	foreign, err := p.CreateTenant(ctx, "Foreign cascade tenant")
	check(err)
	foreignCtx := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"})
	if _, e := p.VPNCascadeStatus(foreignCtx, cascade.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant status read")
	}
	if _, e := p.PutVPNCascade(foreignCtx, tenant, cascade.ID, input); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant cascade write")
	}
	if _, e := p.DeleteVPNCascade(foreignCtx, cascade.ID); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant cascade delete")
	}
	if _, e := p.PutVPNCascade(ctx, tenant, "", input); !errors.Is(e, ErrVPNCascade) {
		t.Fatal("duplicate entry port accepted")
	}
	// Desired-state JSON cannot forge members or silently strip a configured hop.
	current := state(cascade.EntryNodeID)
	var release string
	check(p.Pool.QueryRow(ctx, `SELECT core_release_id::text FROM deployments WHERE node_id=$1::uuid AND generation=$2`, cascade.EntryNodeID, current.Generation).Scan(&release))
	for _, forgery := range []string{"strip", "member", "port"} {
		raw, _ := json.Marshal(current)
		var attempt model.DesiredState
		check(json.Unmarshal(raw, &attempt))
		attempt.Generation++
		switch forgery {
		case "strip":
			attempt.XrayCascades = nil
		case "member":
			attempt.XrayCascades.Entries[0].Clients = nil
		case "port":
			attempt.XrayCascades.Entries[0].Port++
		}
		if e := p.SaveDesiredState(ctx, cascade.EntryNodeID, attempt, release); !errors.Is(e, ErrVPNCascadeIdentity) {
			t.Fatal("forged cascade state accepted", forgery, e)
		}
	}
	if _, _, e := p.LegacyAgentDesiredState(ctx, cascade.EntryNodeID); !errors.Is(e, ErrXrayProfileLegacy) {
		t.Fatal("legacy endpoint exposed cascade")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.33' WHERE id=$1::uuid`, cascade.EntryNodeID)
	check(err)
	if e := p.validateXrayProfileAssignment(ctx, cascade.EntryNodeID, current); !errors.Is(e, ErrNodeRuntime) {
		t.Fatal("old agent accepted cascade assignment")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.34' WHERE id=$1::uuid`, cascade.EntryNodeID)
	check(err)
	// Group membership, explicit disable, and expiry revoke entry access.
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, false)
	check(err)
	memberCount(0)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	memberCount(1)
	_, err = p.SetVPNClientStatus(ctx, client.ID, "disabled")
	check(err)
	memberCount(0)
	_, err = p.SetVPNClientStatus(ctx, client.ID, "active")
	check(err)
	memberCount(1)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()-interval '1 second' WHERE id=$1::uuid`, client.ID)
	check(err)
	n, err := p.ReconcileVPNCascades(ctx)
	check(err)
	if n != 1 {
		t.Fatal("clock expiry not reconciled")
	}
	memberCount(0)
	n, err = p.ReconcileVPNCascades(ctx)
	check(err)
	if n != 0 {
		t.Fatal("unchanged cascade rebuilt repeatedly")
	}
	_, err = p.UpdateVPNClient(ctx, client.ID, nil, nil, nil, true)
	check(err)
	memberCount(1)

	// Traffic from a cascade-only client is charged and removes access at quota.
	_, err = p.SetVPNClientLimits(ctx, client.ID, 100, 0)
	check(err)
	check(p.SaveTrafficDelivery(ctx, cascade.EntryNodeID, model.TrafficDelivery{RecordedAt: time.Now().UTC(), Snapshot: model.ClientTrafficSnapshot{Sequence: 1, Epoch: strings.Repeat("a", 32), Clients: []model.ClientTraffic{{ClientID: client.ID, Uplink: 101}}}}))
	memberCount(0)
	usage, err := p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.UsedBytes != 101 || !usage.QuotaExceeded {
		t.Fatal("cascade traffic missing from quota")
	}
	_, err = p.SetVPNClientLimits(ctx, client.ID, 0, 0)
	check(err)
	memberCount(1)
	// New bot orders also receive a cascade-only group, without a direct grant.
	rawInventory, err := os.ReadFile("../remnawave/testdata/inventory.json")
	check(err)
	var inventory map[string]any
	check(json.Unmarshal(rawInventory, &inventory))
	inventory["source_origin"] = "https://cascade-bot.example.test"
	for i, item := range inventory["users"].([]any) {
		user := item.(map[string]any)
		user["trafficLimitStrategy"] = "NO_RESET"
		user["shortUuid"] = "synthetic-cascade-bot-" + string(rune('a'+i))
		user["subscriptionUrl"] = "https://subscriptions.example.test/" + user["shortUuid"].(string)
	}
	rawInventory, err = json.Marshal(inventory)
	check(err)
	_, report, err := remnawave.Parse(rawInventory)
	check(err)
	imported, _, err := p.StageRemnawaveInventory(ctx, tenant, rawInventory, report.SHA256)
	check(err)
	_, err = p.PrepareBotBridge(ctx, tenant, imported.ID, report.SHA256)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	var squad string
	check(p.Pool.QueryRow(ctx, `SELECT source_uuid::text FROM bot_squads WHERE tenant_id=$1::uuid LIMIT 1`, tenant).Scan(&squad))
	_, err = p.Pool.Exec(ctx, `UPDATE bot_squads SET plan_id=$2::uuid WHERE tenant_id=$1::uuid AND source_uuid=$3::uuid`, tenant, plan.ID, squad)
	check(err)
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	botResult, err := p.BotCreateUser(operator, strings.Repeat("c", 64), BotCreateInput{Username: "cascade_bot_order", DurationDays: 30, TrafficLimitStrategy: "NO_RESET", ActiveInternalSquads: []string{squad}})
	check(err)
	if botResult.Status != 201 {
		t.Fatal("bot cascade order not created")
	}
	memberCount(2)
	var botClient string
	check(p.Pool.QueryRow(ctx, `SELECT client_id::text FROM bot_accounts WHERE tenant_id=$1::uuid AND username='cascade_bot_order'`, tenant).Scan(&botClient))
	_, err = p.DeleteVPNClient(ctx, botClient, "cascade_bot_order")
	check(err)
	memberCount(1)
	// A billing entitlement grants the same independent group profile.
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, false)
	check(err)
	memberCount(0)
	_, err = p.Pool.Exec(ctx, `INSERT INTO billing_entitlements(tenant_id,client_id,plan_id,expires_at) VALUES($1::uuid,$2::uuid,$3::uuid,now()+interval '1 day')`, tenant, client.ID, plan.ID)
	check(err)
	_, err = p.ReconcileVPNCascades(ctx)
	check(err)
	memberCount(1)
	// Group disable removes both the listener and its dedicated exit identity.
	disabled := false
	_, err = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &disabled})
	check(err)
	if state(cascade.EntryNodeID).XrayCascades != nil || state(cascade.ExitNodeID).XrayCascades != nil {
		t.Fatal("disabled group left a cascade active")
	}
	enabled := true
	_, err = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &enabled})
	check(err)
	memberCount(1)
	_, err = p.DeleteVPNClient(ctx, client.ID, client.Name)
	check(err)
	memberCount(0)
	// Metadata does not rotate transit identities or publish new generations.
	input.Name = "🇳🇱 → 🇷🇺 Renamed"
	renamed, err := p.PutVPNCascade(ctx, tenant, cascade.ID, input)
	check(err)
	if len(renamed.Rebuilds) != 0 || state(cascade.ExitNodeID).XrayCascades.Exits[0].ClientID != transit {
		t.Fatal("rename changed runtime identity")
	}
	deleted, err := p.DeleteVPNCascade(ctx, cascade.ID)
	check(err)
	if len(deleted.Rebuilds) != 2 || state(cascade.EntryNodeID).XrayCascades != nil || state(cascade.ExitNodeID).XrayCascades != nil {
		t.Fatal("delete left cascade or transit")
	}
	if len(state(cascade.EntryNodeID).Services) != 1 || len(state(cascade.ExitNodeID).Services) != 1 {
		t.Fatal("ordinary services removed with cascade")
	}
	// Same node, occupied port, management port and cross-tenant inputs are rejected.
	for _, mode := range []string{"same-node", "occupied", "management", "foreign-plan", "foreign-service"} {
		bad := input
		switch mode {
		case "same-node":
			bad.ExitServiceID = bad.EntryServiceID
		case "occupied":
			bad.EntryPort = 443
		case "management":
			bad.EntryPort = 10085
		case "foreign-plan":
			bad.PlanID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		case "foreign-service":
			bad.ExitServiceID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		}
		if _, e := p.PutVPNCascade(ctx, tenant, "", bad); e == nil {
			t.Fatal("invalid topology accepted", mode)
		}
	}
}
