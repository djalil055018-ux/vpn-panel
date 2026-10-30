//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type nodeGroupFixture struct {
	ctx             context.Context
	p               *Postgres
	tenant, node    string
	services, plans []string
	clientSnapshot  string
}

func newNodeGroupFixture(t *testing.T) nodeGroupFixture {
	t.Helper()
	ctx, p := deletionStore(t)
	tenant, services := nativeAccessFixture(t, ctx, p)
	f := nodeGroupFixture{ctx: ctx, p: p, tenant: tenant, services: services}
	f.check(t, p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, services[0]).Scan(&f.node))
	client, err := p.CreateVPNClient(ctx, tenant, "Preserved member", nil)
	f.check(t, err)
	for i, enabled := range []bool{true, false} {
		code := []string{"active-group", "disabled-group"}[i]
		plan, err := p.CreateVPNAccessPlan(ctx, tenant, code, code, enabled)
		f.check(t, err)
		f.plans = append(f.plans, plan.ID)
		for _, service := range services {
			_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service, true)
			f.check(t, err)
		}
		_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
		f.check(t, err)
	}
	f.clientSnapshot = f.clients(t)
	return f
}

func (f nodeGroupFixture) check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func (f nodeGroupFixture) clients(t *testing.T) string {
	t.Helper()
	var value string
	f.check(t, f.p.Pool.QueryRow(f.ctx, `SELECT jsonb_build_object('clients',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM vpn_clients c WHERE tenant_id=$1::uuid),'plans',(SELECT jsonb_agg(to_jsonb(cp) ORDER BY client_id,plan_id) FROM vpn_client_access_plans cp WHERE tenant_id=$1::uuid))::text`, f.tenant).Scan(&value))
	return value
}
func (f nodeGroupFixture) links(t *testing.T, want int) {
	t.Helper()
	var removed, live int
	f.check(t, f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE service_id=$1::uuid),count(*) FILTER(WHERE service_id=$2::uuid) FROM vpn_access_plan_services`, f.services[0], f.services[1]).Scan(&removed, &live))
	if removed != want || live != 2 {
		t.Fatal("group service links changed incorrectly", removed, live)
	}
	if f.clients(t) != f.clientSnapshot {
		t.Fatal("client records or client groups changed")
	}
}
func (f nodeGroupFixture) rejectReattach(t *testing.T) {
	t.Helper()
	if _, err := f.p.SetVPNAccessPlanService(f.ctx, f.plans[0], f.services[0], true); !errors.Is(err, ErrNotFound) {
		t.Fatal("API admitted a removed node service")
	}
	_, err := f.p.Pool.Exec(f.ctx, `INSERT INTO vpn_access_plan_services(tenant_id,plan_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, f.tenant, f.plans[1], f.services[0])
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("database admitted a removed node service")
	}
	f.links(t, 0)
}

func TestNodeRetirementGroupCleanupIntegration(t *testing.T) {
	f := newNodeGroupFixture(t)
	_, err := f.p.Pool.Exec(f.ctx, `UPDATE nodes SET last_seen_at=now()-interval '1 day' WHERE id=$1::uuid`, f.node)
	f.check(t, err)
	var history string
	f.check(t, f.p.Pool.QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(d) ORDER BY generation)::text FROM desired_states d WHERE node_id=$1::uuid`, f.node).Scan(&history))
	// Fail after the status trigger has detached groups: all changes must roll back.
	_, err = f.p.Pool.Exec(f.ctx, `CREATE FUNCTION fail_final_node_delete_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='node.deleted' THEN RAISE EXCEPTION 'synthetic final audit failure';END IF;RETURN NEW;END $$;CREATE TRIGGER fail_final_node_delete_fixture BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_final_node_delete_fixture()`)
	f.check(t, err)
	if _, err = f.p.DeleteNode(f.ctx, f.node, "first", true); err == nil {
		t.Fatal("failed retirement committed")
	}
	f.links(t, 2)
	var receipts int
	f.check(t, f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE node_id=$1::uuid AND event_type='access_plan.node_services_removed'`, f.node).Scan(&receipts))
	if receipts != 0 {
		t.Fatal("rolled back group removal left audit rows")
	}
	_, err = f.p.Pool.Exec(f.ctx, `DROP TRIGGER fail_final_node_delete_fixture ON audit_events;DROP FUNCTION fail_final_node_delete_fixture()`)
	f.check(t, err)
	// The tenant lock and admission trigger serialize concurrent group edits.
	var wg sync.WaitGroup
	errs := make(chan error, 9)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := f.p.SetVPNAccessPlanService(f.ctx, f.plans[0], f.services[0], true)
			if errors.Is(e, ErrNotFound) {
				e = nil
			}
			errs <- e
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _, e := f.p.DeleteNode(f.ctx, f.node, "first", true); errs <- e }()
	wg.Wait()
	close(errs)
	for e := range errs {
		f.check(t, e)
	}
	f.links(t, 0)
	f.rejectReattach(t)
	var after string
	f.check(t, f.p.Pool.QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(d) ORDER BY generation)::text FROM desired_states d WHERE node_id=$1::uuid`, f.node).Scan(&after))
	if history != after {
		t.Fatal("retired execution history changed")
	}
	_, err = f.p.DeleteNode(f.ctx, f.node, "first", true)
	f.check(t, err)
	f.check(t, f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE node_id=$1::uuid AND event_type='access_plan.node_services_removed'`, f.node).Scan(&receipts))
	if receipts != 2 {
		t.Fatal("one cleanup receipt per affected group required", receipts)
	}
}

func TestNodeDecommissionGroupCleanupIntegration(t *testing.T) {
	f := newNodeGroupFixture(t)
	first, err := f.p.DeleteNodeWithOptions(f.ctx, f.node, "first", false, true)
	f.check(t, err)
	if !first.Decommissioning || first.Deleted {
		t.Fatal("safe decommission phase missing")
	}
	f.links(t, 0)
	f.rejectReattach(t)
	if _, err = f.p.DeleteNodeWithOptions(f.ctx, f.node, "first", false, true); !errors.Is(err, ErrNodeDeleteBusy) {
		t.Fatal("empty generation confirmation bypassed")
	}
	_, err = f.p.Pool.Exec(f.ctx, `UPDATE nodes SET applied_generation=$2 WHERE id=$1::uuid`, f.node, first.Generation)
	f.check(t, err)
	_, err = f.p.Pool.Exec(f.ctx, `INSERT INTO node_health(node_id,healthy,applied_generation,checked_at) VALUES($1::uuid,true,$2,now()) ON CONFLICT(node_id) DO UPDATE SET healthy=true,applied_generation=EXCLUDED.applied_generation,checked_at=now()`, f.node, first.Generation)
	f.check(t, err)
	final, err := f.p.DeleteNodeWithOptions(f.ctx, f.node, "first", false, true)
	f.check(t, err)
	if !final.Deleted {
		t.Fatal("safe final retirement missing")
	}
	f.links(t, 0)
	f.rejectReattach(t)
}

// This case is dispatched against schema 76, then applies the real migration.
func TestNodeGroupMembershipBackfillIntegration(t *testing.T) {
	f := newNodeGroupFixture(t)
	var triggers int
	f.check(t, f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_trigger WHERE tgname='node_group_services_removed'`).Scan(&triggers))
	if triggers != 0 {
		t.Fatal("legacy schema fixture required")
	}
	_, err := f.p.Pool.Exec(f.ctx, `UPDATE nodes SET last_seen_at=now()-interval '1 day' WHERE id=$1::uuid`, f.node)
	f.check(t, err)
	_, err = f.p.DeleteNode(f.ctx, f.node, "first", true)
	f.check(t, err)
	f.links(t, 2)
	migration, err := os.ReadFile("../../migrations/000077_node_group_service_cleanup.sql")
	f.check(t, err)
	// A failure during historical cleanup must roll back its DDL as well.
	_, err = f.p.Pool.Exec(f.ctx, `CREATE FUNCTION fail_group_migration_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='access_plan.node_services_removed' THEN RAISE EXCEPTION 'synthetic migration audit failure';END IF;RETURN NEW;END $$;CREATE TRIGGER fail_group_migration_fixture BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_group_migration_fixture()`)
	f.check(t, err)
	conn, err := f.p.Pool.Acquire(f.ctx)
	f.check(t, err)
	_, applyErr := conn.Exec(f.ctx, string(migration))
	_, rollbackErr := conn.Exec(f.ctx, "ROLLBACK")
	conn.Release()
	f.check(t, rollbackErr)
	if applyErr == nil {
		t.Fatal("failed historical cleanup committed")
	}
	f.check(t, f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_trigger WHERE tgname IN ('node_group_services_removed','access_plan_service_node_admission')`).Scan(&triggers))
	if triggers != 0 {
		t.Fatal("failed migration left partial guards")
	}
	f.links(t, 2)
	_, err = f.p.Pool.Exec(f.ctx, `DROP TRIGGER fail_group_migration_fixture ON audit_events;DROP FUNCTION fail_group_migration_fixture()`)
	f.check(t, err)
	_, err = f.p.Pool.Exec(f.ctx, string(migration))
	f.check(t, err)
	f.links(t, 0)
	f.rejectReattach(t)
}
