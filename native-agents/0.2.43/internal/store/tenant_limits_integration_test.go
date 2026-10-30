//go:build integration

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestTenantResourceLimitsConcurrentIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(45*time.Second))
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
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var tenant, other string
	for _, id := range []*string{&tenant, &other} {
		check(p.Pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('CODEX-LIMITS') RETURNING id::text`).Scan(id))
		defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, *id)
	}
	initial, err := p.TenantResourceLimits(ctx, tenant)
	check(err)
	if initial.MaxClients != 0 || initial.MaxPlans != 0 {
		t.Fatal("existing defaults restricted")
	}
	_, err = p.SetTenantResourceLimits(ctx, tenant, 2, 2)
	check(err)
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator", ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
	if _, err = p.TenantResourceLimits(scoped, other); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign limit visible")
	}
	if _, err = p.SetTenantResourceLimits(scoped, tenant, 100, 100); !errors.Is(err, ErrNotFound) {
		t.Fatal("tenant changed own limit")
	}
	for _, kind := range []string{"client", "plan"} {
		var okay, rejected, unexpected atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				var e error
				if kind == "client" {
					_, e = p.CreateVPNClient(scoped, tenant, fmt.Sprintf("Concurrent %d", i), nil)
				} else {
					_, e = p.CreateVPNAccessPlan(scoped, tenant, fmt.Sprintf("Plan %d", i), fmt.Sprintf("p-%d", i), true)
				}
				if e == nil {
					okay.Add(1)
				} else if errors.Is(e, ErrTenantQuota) {
					rejected.Add(1)
				} else {
					unexpected.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if okay.Load() != 2 || rejected.Load() != 10 || unexpected.Load() != 0 {
			t.Fatal("concurrent resource creation exceeded limit or failed unexpectedly")
		}
	}
	limits, err := p.TenantResourceLimits(ctx, tenant)
	check(err)
	if limits.Clients != 2 || limits.Plans != 2 {
		t.Fatal("usage counts incorrect")
	}
	if _, err = p.SetTenantResourceLimits(ctx, tenant, 1, 2); !errors.Is(err, ErrTenantQuota) {
		t.Fatal("limit below usage accepted")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='disabled' WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	if _, err = p.CreateVPNClient(ctx, tenant, "disabled records still count", nil); !errors.Is(err, ErrTenantQuota) {
		t.Fatal("disabled clients bypassed limit")
	}
	_, err = p.SetTenantResourceLimits(ctx, tenant, 0, 0)
	check(err)
	_, err = p.CreateVPNClient(ctx, tenant, "unlimited", nil)
	check(err)
	_, err = p.CreateVPNAccessPlan(ctx, tenant, "unlimited", "unlimited", true)
	check(err)
}
