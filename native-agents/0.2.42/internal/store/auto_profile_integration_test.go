//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestAutoProfileEligibilityIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test DB")
	}
	defer p.Close()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var db string
	check(p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&db))
	if !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("test database required")
	}
	tenant, services := nativeAccessFixture(t, ctx, p)
	settings, err := p.GetAutoProfileSettings(ctx, tenant)
	check(err)
	if settings.Enabled || settings.Name != "Авто" || !settings.RussiaDirect {
		t.Fatal("safe defaults")
	}
	settings.Enabled = true
	settings.Name = "Мой маршрут"
	_, err = p.SetAutoProfileSettings(ctx, tenant, settings)
	check(err)
	foreign, err := p.CreateTenant(ctx, "Auto foreign")
	check(err)
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID})
	if _, err = p.GetAutoProfileSettings(scoped, tenant); !errors.Is(err, ErrNotFound) {
		t.Fatal("tenant read boundary")
	}
	if _, err = p.SetAutoProfileSettings(scoped, tenant, settings); !errors.Is(err, ErrNotFound) {
		t.Fatal("tenant write boundary")
	}
	client, err := p.CreateVPNClient(ctx, tenant, "Auto fixture", nil)
	check(err)
	// Synthetic grants, metrics and health belong only to this disposable DB.
	for _, service := range services {
		_, err = p.Pool.Exec(ctx, `INSERT INTO vpn_client_services(tenant_id,client_id,service_id) VALUES($1,$2,$3)`, tenant, client.ID, service)
		check(err)
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET applied_generation=desired_generation,last_seen_at=now() WHERE tenant_id=$1;`, tenant)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE deployments d SET status='healthy' FROM nodes n WHERE d.node_id=n.id AND n.tenant_id=$1 AND d.generation=n.applied_generation AND d.status IN ('pending','applying')`, tenant)
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO node_health(node_id,healthy,applied_generation) SELECT id,true,applied_generation FROM nodes WHERE tenant_id=$1`, tenant)
	check(err)
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if len(connections) != 2 {
		t.Fatal("fixture grants")
	}
	expect := func(want int) {
		t.Helper()
		auto, e := p.SubscriptionAutoForConnections(ctx, tenant, client.ID, connections)
		check(e)
		if len(auto.Candidates) != want {
			t.Fatalf("eligible %d want %d", len(auto.Candidates), want)
		}
	}
	expect(2)
	// An unclaimed historical deployment does not override a newer healthy
	// runtime. A physically active execution owner still excludes that node.
	var historical string
	check(p.Pool.QueryRow(ctx, `SELECT d.id::text FROM deployments d JOIN nodes n ON n.id=d.node_id WHERE d.node_id=(SELECT node_id FROM vpn_services WHERE id=$1) AND d.generation<n.applied_generation AND d.status='pending' ORDER BY d.generation LIMIT 1`, services[0]).Scan(&historical))
	expect(2)
	_, err = p.Pool.Exec(ctx, `INSERT INTO deployment_execution_leases(deployment_id,node_id,generation,execution_id,execution_epoch,state,owner_instance_id,lease_token_hash,claimed_at,renewed_at,lease_expires_at)
 SELECT id,node_id,generation,execution_id,execution_epoch,'active',gen_random_uuid(),repeat('a',64),now(),now(),now()+interval '1 minute' FROM deployments WHERE id=$1
 ON CONFLICT(deployment_id) DO UPDATE SET state='active',owner_instance_id=excluded.owner_instance_id,lease_token_hash=excluded.lease_token_hash,claimed_at=excluded.claimed_at,renewed_at=excluded.renewed_at,lease_expires_at=excluded.lease_expires_at`, historical)
	check(err)
	expect(1)
	_, err = p.Pool.Exec(ctx, `UPDATE deployment_execution_leases SET state='fenced',fenced_at=now(),fencing_reason='synthetic test complete' WHERE deployment_id=$1`, historical)
	check(err)
	expect(2)
	_, err = p.Pool.Exec(ctx, `UPDATE node_health SET checked_at=now()-interval '3 minutes' WHERE node_id=(SELECT node_id FROM vpn_services WHERE id=$1)`, services[0])
	check(err)
	expect(1)
	_, err = p.Pool.Exec(ctx, `UPDATE node_health SET checked_at=now(),healthy=false WHERE node_id=(SELECT node_id FROM vpn_services WHERE id=$1)`, services[0])
	check(err)
	expect(1)
	_, err = p.Pool.Exec(ctx, `UPDATE node_health SET healthy=true WHERE node_id=(SELECT node_id FROM vpn_services WHERE id=$1)`, services[0])
	check(err)
	expect(2)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET desired_generation=desired_generation+1 WHERE id=(SELECT node_id FROM vpn_services WHERE id=$1)`, services[0])
	check(err)
	expect(1)
	_, err = p.Pool.Exec(ctx, `DELETE FROM vpn_client_services WHERE client_id=$1 AND service_id=$2`, client.ID, services[1])
	check(err)
	expect(0)
	// Even stale caller connection material cannot reopen revoked/expired access.
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='disabled' WHERE id=$1`, client.ID)
	check(err)
	expect(0)
	other, e := p.SubscriptionAutoForConnections(ctx, foreign.ID, client.ID, connections)
	check(e)
	if len(other.Candidates) != 0 {
		t.Fatal("foreign grant")
	}
}
