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

func TestRemnawaveDeltaReadOnlyIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(60*time.Second))
	defer cancel()
	p, e := NewPostgres(ctx, dsn)
	if e != nil {
		t.Fatal("isolated database unavailable")
	}
	defer p.Close()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var db string
	check(p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&db))
	if !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	tenant, e := p.CreateTenant(ctx, "Delta synthetic")
	check(e)
	defer func() {
		c := context.Background()
		_, e := p.Pool.Exec(c, `DELETE FROM remnawave_import_clients WHERE import_id IN (SELECT id FROM remnawave_imports WHERE tenant_id=$1::uuid)`, tenant.ID)
		check(e)
		_, e = p.Pool.Exec(c, `DELETE FROM remnawave_imports WHERE tenant_id=$1::uuid`, tenant.ID)
		check(e)
		_, e = p.Pool.Exec(c, `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
		check(e)
	}()
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	check(e)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	inv["source_origin"] = "https://delta-" + tenant.ID + ".example.test"
	for _, row := range inv["users"].([]any) {
		var id string
		check(p.Pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id))
		row.(map[string]any)["vlessUuid"] = id
	}
	raw, e = json.Marshal(inv)
	check(e)
	_, report, e := remnawave.Parse(raw)
	check(e)
	staged, created, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(e)
	if !created {
		t.Fatal("delta fixture already existed")
	}
	inv["users"].([]any)[0].(map[string]any)["status"] = "DISABLED"
	after, e := json.Marshal(inv)
	check(e)
	delta, e := p.PreviewRemnawaveDelta(ctx, staged.ID, tenant.ID, after)
	check(e)
	if delta.ChangedUsers != 1 || delta.ChangedCategories["status"] != 1 || !delta.ReviewRequired || delta.CutoverReady {
		t.Fatal("delta counts differ")
	}
	var kept []byte
	check(p.Pool.QueryRow(ctx, `SELECT inventory FROM remnawave_imports WHERE id=$1::uuid`, staged.ID).Scan(&kept))
	if !bytes.Equal(raw, kept) {
		t.Fatal("preview replaced source inventory")
	}
	for _, role := range []string{"admin", "monitor"} {
		restricted := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: role}})
		if _, e = p.PreviewRemnawaveDelta(restricted, staged.ID, tenant.ID, after); !errors.Is(e, ErrNotFound) {
			t.Fatal("non-owner read source delta")
		}
	}
	restricted := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	if _, e = p.PreviewRemnawaveDelta(restricted, staged.ID, tenant.ID, after); !errors.Is(e, ErrNotFound) {
		t.Fatal("tenant read source inventory")
	}
	if _, e = p.PreviewRemnawaveDelta(ctx, staged.ID, "00000000-0000-4000-8000-000000000001", after); !errors.Is(e, ErrNotFound) {
		t.Fatal("delta bound to wrong target tenant")
	}
	clients, e := p.ListVPNClients(ctx, tenant.ID)
	check(e)
	for _, c := range clients {
		if !c.RemnawaveHold || c.Status != "disabled" {
			t.Fatal("preview altered held client")
		}
	}
	var audits int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND event_type='remnawave.inventory_staged'`, tenant.ID).Scan(&audits))
	if audits != 1 {
		t.Fatal("preview created staging audit")
	}
}
