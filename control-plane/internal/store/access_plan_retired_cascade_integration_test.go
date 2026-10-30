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

func TestAccessPlanRetiredCascadeIntegration(t *testing.T) {
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
	plan, err := p.CreateVPNAccessPlan(ctx, tenant, "Retired cascade group", "retired-cascade-group", true)
	check(err)
	for _, service := range services {
		_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service, true)
		check(err)
	}
	existing, err := p.CreateVPNClient(ctx, tenant, "Existing member", nil)
	check(err)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, existing.ID, true)
	check(err)
	cascade, err := p.PutVPNCascade(ctx, tenant, "", model.VPNCascadeInput{Name: "Retired exit", PlanID: plan.ID, EntryServiceID: services[0], ExitServiceID: services[1], EntryPort: 9443, Enabled: true})
	check(err)
	exit := cascade.Cascade.ExitNodeID
	// Model an already retired exit with historical group/cascade references.
	// Keep all real retirement fences enabled, including immutable history.
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_services SET enabled=false WHERE node_id=$1::uuid;
`, exit)
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO node_retirements(node_id,confirmed_name,server_stopped) SELECT id,name,true FROM nodes WHERE id=$1::uuid`, exit)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET status='retired',agent_token_hash=NULL,bootstrap_token_hash=NULL WHERE id=$1::uuid`, exit)
	check(err)
	var generation int64
	check(p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, exit).Scan(&generation))
	newClient, err := p.CreateVPNClient(ctx, tenant, "New member", nil)
	check(err)
	assertLive := func(want int) {
		t.Helper()
		state, ok, e := p.LatestDesiredState(ctx, cascade.Cascade.EntryNodeID)
		check(e)
		if !ok || len(state.Services) != 1 || len(state.Services[0].Clients) != want {
			t.Fatal("live ordinary access not rebuilt")
		}
		if state.XrayCascades != nil && len(state.XrayCascades.Entries) != 0 {
			t.Fatal("inactive cascade still assigned")
		}
		var after int64
		check(p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, exit).Scan(&after))
		if after != generation {
			t.Fatal("retired node generation changed")
		}
	}
	r, err := p.SetVPNClientAccessPlan(ctx, plan.ID, newClient.ID, true)
	check(err)
	if !r.Changed || len(r.Rebuilds) != 1 {
		t.Fatal("new member must rebuild only the live node")
	}
	assertLive(2)
	r, err = p.SetVPNAccessPlanService(ctx, plan.ID, services[1], false)
	check(err)
	if r.Changed {
		t.Fatal("retirement must already have removed the service membership")
	}
	detail, err := p.GetVPNAccessPlan(ctx, plan.ID)
	check(err)
	if len(detail.ServiceIDs) != 1 || detail.ServiceIDs[0] != services[0] {
		t.Fatal("live service membership changed")
	}
	assertLive(2)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, newClient.ID, false)
	check(err)
	assertLive(1)
	enabled := false
	_, err = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &enabled})
	check(err)
	assertLive(0)
	var historical bool
	check(p.Pool.QueryRow(ctx, `SELECT enabled FROM vpn_cascades WHERE id=$1::uuid`, cascade.Cascade.ID).Scan(&historical))
	if !historical {
		t.Fatal("historical cascade definition was overwritten")
	}
}
