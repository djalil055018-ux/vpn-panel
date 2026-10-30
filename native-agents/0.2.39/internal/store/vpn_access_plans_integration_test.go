//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"vpn-platform/internal/model"
)

// This suite creates its own native nodes in a disposable database.
func TestAccessPlanAtomicIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database connection failed")
	}
	defer p.Close()
	var dbName string
	if err = p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil || !strings.HasPrefix(dbName, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	tenant, services := nativeAccessFixture(t, ctx, p)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	plan, err := p.CreateVPNAccessPlan(ctx, tenant, "Atomic integration", "codex-atomic-integration", true)
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant, "CODEX-ATOMIC-INTEGRATION", nil)
	check(err)
	defer func() {
		_, _ = p.Pool.Exec(context.Background(), `DELETE FROM vpn_access_plans WHERE id=$1::uuid`, plan.ID)
		_, _ = p.Pool.Exec(context.Background(), `DELETE FROM vpn_clients WHERE id=$1::uuid`, client.ID)
	}()
	for _, service := range services {
		r, err := p.SetVPNAccessPlanService(ctx, plan.ID, service, true)
		check(err)
		if !r.Changed || len(r.Rebuilds) != 0 {
			t.Fatal("empty plan should not rebuild")
		}
	}
	checkAccess := func(want int) {
		t.Helper()
		var count int
		check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_effective_client_services WHERE client_id=$1::uuid`, client.ID).Scan(&count))
		if count != want {
			t.Fatalf("effective access = %d, want %d", count, want)
		}
	}
	checkDesired := func(want int) {
		t.Helper()
		var count int
		check(p.Pool.QueryRow(ctx, `SELECT count(DISTINCT n.id) FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation,
	jsonb_array_elements(ds.document->'services') s,jsonb_array_elements(s->'clients') c WHERE c->>'id'=$1`, client.VLESSUUID).Scan(&count))
		if count != want {
			t.Fatalf("desired client nodes = %d, want %d", count, want)
		}
	}
	r, err := p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	if len(r.Rebuilds) != 2 {
		t.Fatal("attach must rebuild both nodes")
	}
	checkAccess(2)
	checkDesired(2)
	r, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	if r.Changed || len(r.Rebuilds) != 0 {
		t.Fatal("duplicate attach rebuilt nodes")
	}
	r, err = p.SetVPNAccessPlanService(ctx, plan.ID, services[1], false)
	check(err)
	checkAccess(1)
	checkDesired(1)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, services[1], true)
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO vpn_client_services(tenant_id,client_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, tenant, client.ID, services[0])
	check(err)
	disabled := false
	_, err = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &disabled})
	check(err)
	checkAccess(1)
	checkDesired(1)
	enabled := true
	_, err = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &enabled})
	check(err)
	checkAccess(2)
	checkDesired(2)
	name := "Renamed"
	r, err = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Name: &name})
	check(err)
	if len(r.Rebuilds) != 0 {
		t.Fatal("metadata rebuilt nodes")
	}
	// A missing desired-state baseline must roll back membership AND any earlier node rebuild.
	var badNode, badService string
	check(p.Pool.QueryRow(ctx, `INSERT INTO nodes(tenant_id,name) VALUES($1::uuid,'CODEX-BAD-NODE') RETURNING id::text`, tenant).Scan(&badNode))
	defer p.Pool.Exec(context.Background(), `DELETE FROM nodes WHERE id=$1::uuid`, badNode)
	check(p.Pool.QueryRow(ctx, `INSERT INTO vpn_services(tenant_id,node_id,name,protocol,port,transport,security,enabled)
	VALUES($1::uuid,$2::uuid,'bad','vless',443,'tcp','reality',true) RETURNING id::text`, tenant, badNode).Scan(&badService))
	var before, after int64
	check(p.Pool.QueryRow(ctx, `SELECT sum(desired_generation) FROM nodes`).Scan(&before))
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, badService, true)
	if err == nil {
		t.Fatal("missing baseline accepted")
	}
	check(p.Pool.QueryRow(ctx, `SELECT sum(desired_generation) FROM nodes`).Scan(&after))
	if before != after {
		t.Fatal("partial generations committed")
	}
	detail, err := p.GetVPNAccessPlan(ctx, plan.ID)
	check(err)
	if len(detail.ServiceIDs) != 2 {
		t.Fatal("failed service membership committed")
	}
	// Tenant boundaries are checked before inserting either membership type.
	other, err := p.CreateTenant(ctx, "CODEX-OTHER-TENANT")
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, other.ID)
	foreign, err := p.CreateVPNClient(ctx, other.ID, "foreign", nil)
	check(err)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, foreign.ID, true)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant client accepted")
	}
	otherPlan, err := p.CreateVPNAccessPlan(ctx, other.ID, "Other", "other", true)
	check(err)
	_, err = p.SetVPNAccessPlanService(ctx, otherPlan.ID, services[0], true)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-tenant service accepted")
	}
	// Concurrent repeated assignment is one state change and one pair of generations.
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, false)
	check(err)
	checkAccess(1)
	checkDesired(1)
	var wg sync.WaitGroup
	results := make(chan model.VPNAccessPlanMutation, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
			results <- r
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		check(e)
	}
	changed := 0
	for r := range results {
		if r.Changed {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("concurrent assignments changed %d times", changed)
	}
	_, err = p.DeleteVPNAccessPlan(ctx, plan.ID)
	check(err)
	checkAccess(1)
	checkDesired(1)
	_, err = p.GetVPNAccessPlan(ctx, plan.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted plan still exists")
	}
}
