//go:build integration

package store

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVPNClientLifecycleIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(90*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test connection failed")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, services := nativeAccessFixture(t, ctx, p)
	sweden, poland := services[0], services[1]
	client, err := p.CreateVPNClient(ctx, tenant, "CODEX-LIFECYCLE-INTEGRATION", nil)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM vpn_clients WHERE id=$1::uuid`, client.ID)
	plan, err := p.CreateVPNAccessPlan(ctx, tenant, "Lifecycle", "codex-lifecycle-integration", true)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM vpn_access_plans WHERE id=$1::uuid`, plan.ID)
	_, err = p.Pool.Exec(ctx, `INSERT INTO vpn_client_services(tenant_id,client_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, tenant, client.ID, sweden)
	check(err)
	for _, service := range []string{sweden, poland} {
		_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service, true)
		check(err)
	}
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	checkDesired := func(want int) {
		t.Helper()
		var count int
		check(p.Pool.QueryRow(ctx, `SELECT count(DISTINCT n.id) FROM nodes n JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation,jsonb_array_elements(ds.document->'services') s,jsonb_array_elements(s->'clients') u WHERE u->>'id'=$1`, client.VLESSUUID).Scan(&count))
		if count != want {
			t.Fatalf("desired node presence=%d want=%d", count, want)
		}
	}
	generations := func() int64 {
		t.Helper()
		var n int64
		check(p.Pool.QueryRow(ctx, `SELECT sum(desired_generation) FROM nodes`).Scan(&n))
		return n
	}
	checkDesired(2)
	_, err = p.SetVPNClientStatus(ctx, client.ID, "disabled")
	check(err)
	checkDesired(0)
	n := generations()
	_, err = p.SetVPNClientStatus(ctx, client.ID, "disabled")
	check(err)
	if n != generations() {
		t.Fatal("duplicate disable rebuilt")
	}
	_, err = p.SetVPNClientStatus(ctx, client.ID, "active")
	check(err)
	checkDesired(2)
	n = generations()
	name := "renamed lifecycle"
	_, err = p.UpdateVPNClient(ctx, client.ID, &name, nil, nil, false)
	check(err)
	if n != generations() {
		t.Fatal("metadata rebuilt")
	}
	expires := time.Now().UTC().Add(2 * time.Second)
	_, err = p.UpdateVPNClient(ctx, client.ID, nil, nil, &expires, true)
	check(err)
	if n != generations() {
		t.Fatal("future expiry rebuilt early")
	}
	time.Sleep(2500 * time.Millisecond)
	count, err := p.ReconcileInactiveVPNClients(ctx)
	check(err)
	if count < 2 {
		t.Fatal("expiry did not rebuild both nodes")
	}
	checkDesired(0)
	n = generations()
	_, err = p.ReconcileInactiveVPNClients(ctx)
	check(err)
	if n != generations() {
		t.Fatal("expiry repeated rebuild")
	}
	renewed, err := p.UpdateVPNClient(ctx, client.ID, nil, nil, nil, true)
	check(err)
	if renewed.EffectiveStatus != "active" {
		t.Fatal("renewal inactive")
	}
	checkDesired(2)
	var badNode, badService string
	check(p.Pool.QueryRow(ctx, `INSERT INTO nodes(tenant_id,name) VALUES($1::uuid,'CODEX-LIFECYCLE-BAD-NODE') RETURNING id::text`, tenant).Scan(&badNode))
	defer p.Pool.Exec(context.Background(), `DELETE FROM nodes WHERE id=$1::uuid`, badNode)
	check(p.Pool.QueryRow(ctx, `INSERT INTO vpn_services(tenant_id,node_id,name,protocol,port,transport,security,enabled) VALUES($1::uuid,$2::uuid,'bad','vless',19499,'tcp','reality',true) RETURNING id::text`, tenant, badNode).Scan(&badService))
	_, err = p.Pool.Exec(ctx, `INSERT INTO vpn_client_services(tenant_id,client_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, tenant, client.ID, badService)
	check(err)
	n = generations()
	_, err = p.SetVPNClientStatus(ctx, client.ID, "disabled")
	if err == nil {
		t.Fatal("missing baseline accepted")
	}
	if n != generations() {
		t.Fatal("partial generations committed")
	}
	unchanged, err := p.GetVPNClient(ctx, client.ID)
	check(err)
	if unchanged.Status != "active" {
		t.Fatal("partial client update committed")
	}
	_, err = p.Pool.Exec(ctx, `DELETE FROM nodes WHERE id=$1::uuid`, badNode)
	check(err)
	// The common tenant lock prevents a simultaneous plan edit from committing
	// a stale client eligibility snapshot after the client was disabled.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); _, err := p.SetVPNClientStatus(ctx, client.ID, "disabled"); errs <- err }()
	go func() { defer wg.Done(); _, err := p.SetVPNAccessPlanService(ctx, plan.ID, poland, false); errs <- err }()
	wg.Wait()
	close(errs)
	for err := range errs {
		check(err)
	}
	checkDesired(0)
	var direct int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_services WHERE client_id=$1::uuid`, client.ID).Scan(&direct))
	if direct != 1 {
		t.Fatal("manual grant removed")
	}
}
