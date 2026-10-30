//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/security"
)

func TestResellerIsolationAndDependencyIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	p, err := NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("isolated database required")
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
	ids := []string{}
	defer func() {
		for i := len(ids) - 1; i >= 0; i-- {
			_, e := p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, ids[i])
			if e != nil {
				t.Error("fixture cleanup failed")
			}
		}
	}()
	owner := func() string {
		var id string
		check(p.Pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('CODEX-RESELLER-INTEGRATION') RETURNING id::text`).Scan(&id))
		ids = append(ids, id)
		return id
	}
	a, b := owner(), owner()
	expiry := time.Now().UTC().Add(48 * time.Hour)
	pa, err := p.CreateTenantAPIToken(ctx, a, "parent-a", "reseller", security.HashToken(a), expiry)
	check(err)
	pb, err := p.CreateTenantAPIToken(ctx, b, "parent-b", "reseller", security.HashToken(b), expiry)
	check(err)
	ca, cb := WithTenantPrincipal(ctx, pa), WithTenantPrincipal(ctx, pb)
	child, err := p.CreateResellerChild(ca, "Child A")
	check(err)
	ids = append(ids, child.ID)
	other, err := p.CreateResellerChild(cb, "Child B")
	check(err)
	ids = append(ids, other.ID)
	list, err := p.ListResellerChildren(ca, a)
	check(err)
	if len(list) != 1 || list[0].ID != child.ID {
		t.Fatal("child listing wrong")
	}
	if _, err = p.ListResellerChildren(ca, b); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-parent listing allowed")
	}
	hash := security.HashToken(child.ID)
	key, err := p.CreateResellerChildToken(ca, child.ID, "child", "operator", hash, expiry.Add(-time.Hour))
	check(err)
	if _, err = p.AuthenticateTenantAPIToken(ctx, hash); err != nil {
		t.Fatal("delegated authentication failed")
	}
	if _, err = p.CreateResellerChildToken(cb, child.ID, "foreign", "viewer", security.HashToken("foreign"), expiry.Add(-time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign child key created")
	}
	if _, err = p.ListResellerChildTokens(cb, child.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign keys visible")
	}
	if _, err = p.RevokeResellerChildToken(cb, child.ID, key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign key revoked")
	}
	for _, role := range []string{"reseller", "admin"} {
		if _, err = p.CreateResellerChildToken(ca, child.ID, "escalation", role, security.HashToken(role), expiry.Add(-time.Hour)); !errors.Is(err, ErrResellerHierarchy) {
			t.Fatal("role escalation allowed")
		}
	}
	if _, err = p.CreateResellerChildToken(ca, child.ID, "long", "viewer", security.HashToken("long"), expiry.Add(time.Hour)); !errors.Is(err, ErrResellerHierarchy) {
		t.Fatal("child outlived parent")
	}
	if _, err = p.CreateTenantAPIToken(ctx, child.ID, "nested", "reseller", security.HashToken("nested"), expiry); !errors.Is(err, ErrResellerHierarchy) {
		t.Fatal("nested reseller allowed")
	}
	if _, err = p.CreateTenantAPIToken(ca, a, "bypass", "operator", security.HashToken("bypass"), expiry); !errors.Is(err, ErrNotFound) {
		t.Fatal("scoped admin create allowed")
	}
	if _, err = p.ListTenantAPITokens(ca, a); !errors.Is(err, ErrNotFound) {
		t.Fatal("scoped admin listing allowed")
	}
	if _, err = p.RevokeTenantAPIToken(ca, pa.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("scoped admin revoke allowed")
	}
	independentHash := security.HashToken("independent-" + child.ID)
	independent, err := p.CreateTenantAPIToken(ctx, child.ID, "admin-independent", "operator", independentHash, expiry)
	check(err)
	if _, err = p.RevokeResellerChildToken(ca, child.ID, independent.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("admin key revoked by reseller")
	}
	keys, err := p.ListResellerChildTokens(ca, child.ID)
	check(err)
	if len(keys) != 1 {
		t.Fatal("admin key leaked to reseller")
	}
	childCtx := WithTenantPrincipal(ctx, key)
	if _, err = p.CreateResellerChild(childCtx, "nested"); !errors.Is(err, ErrNotFound) {
		t.Fatal("operator created child")
	}
	// Authentication checks issuer state independently of cascade metadata.
	_, err = p.Pool.Exec(ctx, `UPDATE tenant_api_tokens SET created_at=now()-interval '2 days',expires_at=now()-interval '1 second' WHERE id=$1::uuid`, pa.ID)
	check(err)
	if _, err = p.AuthenticateTenantAPIToken(ctx, hash); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired parent accepted")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE tenant_api_tokens SET expires_at=$2 WHERE id=$1::uuid`, pa.ID, expiry)
	check(err)
	_, err = p.RevokeTenantAPIToken(ctx, pa.ID)
	check(err)
	_, err = p.RevokeTenantAPIToken(ctx, pa.ID)
	check(err)
	if _, err = p.AuthenticateTenantAPIToken(ctx, hash); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked parent child accepted")
	}
	var revoked bool
	check(p.Pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM tenant_api_tokens WHERE id=$1::uuid`, key.ID).Scan(&revoked))
	if !revoked {
		t.Fatal("cascade metadata missing")
	}
	if _, err = p.AuthenticateTenantAPIToken(ctx, independentHash); err != nil {
		t.Fatal("independent admin key affected")
	}
	if _, err = p.CreateResellerChild(ca, "stale"); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale authenticated parent created child")
	}
	// The limit counts children across all credentials for the same parent.
	for i := 1; i < 20; i++ {
		extra, e := p.CreateResellerChild(cb, "Limit child")
		check(e)
		ids = append(ids, extra.ID)
	}
	if _, err = p.CreateResellerChild(cb, "Overflow"); !errors.Is(err, ErrResellerLimit) {
		t.Fatal("child limit ignored")
	}
}
