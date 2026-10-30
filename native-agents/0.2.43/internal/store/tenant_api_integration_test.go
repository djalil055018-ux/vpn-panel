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

func TestTenantScopeStoreIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated DSN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(30*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test connection failed")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	a, err := p.CreateTenant(ctx, "CODEX-SCOPE-STORE-A")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, a.ID)
	b, err := p.CreateTenant(ctx, "CODEX-SCOPE-STORE-B")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, b.ID)
	plan, err := p.CreateVPNAccessPlan(ctx, b.ID, "foreign", "foreign", true)
	if err != nil {
		t.Fatal(err)
	}
	client, err := p.CreateVPNClient(ctx, b.ID, "foreign", nil)
	if err != nil {
		t.Fatal(err)
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: a.ID, ID: a.ID, Role: "operator"})
	expectDenied := func(err error) {
		t.Helper()
		if !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-tenant operation was not denied")
		}
	}
	_, err = p.GetVPNAccessPlan(scoped, plan.ID)
	expectDenied(err)
	_, err = p.ListVPNAccessPlans(scoped, b.ID)
	expectDenied(err)
	_, err = p.CreateVPNAccessPlan(scoped, b.ID, "bad", "bad", true)
	expectDenied(err)
	name := "bad"
	_, err = p.UpdateVPNAccessPlan(scoped, plan.ID, AccessPlanUpdate{Name: &name})
	expectDenied(err)
	_, err = p.DeleteVPNAccessPlan(scoped, plan.ID)
	expectDenied(err)
	_, err = p.SetVPNClientAccessPlan(scoped, plan.ID, client.ID, true)
	expectDenied(err)
	_, err = p.GetVPNClient(scoped, client.ID)
	expectDenied(err)
	_, err = p.ListVPNClients(scoped, b.ID)
	expectDenied(err)
	_, err = p.CreateVPNClient(scoped, b.ID, "bad", nil)
	expectDenied(err)
	unchanged, err := p.GetVPNAccessPlan(ctx, plan.ID)
	if err != nil || unchanged.Name != "foreign" || len(unchanged.ClientIDs) != 0 {
		t.Fatal("foreign plan changed")
	}
}
