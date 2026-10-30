//go:build integration

package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestAuditHistoryPaginationAndRedactionIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(30*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("isolated DB required")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing live DB")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var tenant string
	check(p.Pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('CODEX-AUDIT-INTEGRATION') RETURNING id::text`).Scan(&tenant))
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant)
	at := time.Now().UTC()
	for _, id := range []string{"00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"} {
		_, err = p.Pool.Exec(ctx, `INSERT INTO audit_events(id,tenant_id,event_type,actor_type,actor_id,payload,created_at) VALUES($1::uuid,$2::uuid,'codex.audit_test','admin','SECRET-MARKER-NEVER-RETURN',jsonb_build_object('private_key','SECRET-MARKER-NEVER-RETURN','subscription_url','SECRET-MARKER-NEVER-RETURN'),$3)`, id, tenant, at)
		check(err)
	}
	page, err := p.AuditHistory(ctx, tenant, "codex.audit_test", "admin", nil, 2)
	check(err)
	if len(page.Events) != 2 || page.NextCursor == nil || !strings.HasSuffix(page.Events[0].ID, "3") {
		t.Fatal("first page order incorrect")
	}
	raw, err := json.Marshal(page)
	check(err)
	if strings.Contains(string(raw), "SECRET-MARKER") || strings.Contains(string(raw), "payload") {
		t.Fatal("audit leaked legacy secrets")
	}
	next, err := p.AuditHistory(ctx, tenant, "codex.audit_test", "admin", page.NextCursor, 2)
	check(err)
	if len(next.Events) != 1 || next.NextCursor != nil || !strings.HasSuffix(next.Events[0].ID, "1") {
		t.Fatal("cursor lost or repeated equal-timestamp rows")
	}
	none, err := p.AuditHistory(ctx, tenant, "codex.audit_test", "system", nil, 2)
	check(err)
	if len(none.Events) != 0 {
		t.Fatal("actor filter ignored")
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	if _, err = p.AuditHistory(scoped, tenant, "", "", nil, 50); err != ErrNotFound {
		t.Fatal("tenant read global audit")
	}
}
