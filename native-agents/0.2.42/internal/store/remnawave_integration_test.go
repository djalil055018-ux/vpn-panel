//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
)

func TestRemnawaveHeldStagingIntegration(t *testing.T) {
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
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, err := p.CreateTenant(ctx, "Remnawave synthetic staging")
	check(err)
	other, err := p.CreateTenant(ctx, "Remnawave other synthetic tenant")
	check(err)
	defer func() {
		cleanCtx := context.Background()
		for _, id := range []string{tenant.ID, other.ID} {
			_, e := p.Pool.Exec(cleanCtx, `DELETE FROM remnawave_import_clients WHERE import_id IN (SELECT id FROM remnawave_imports WHERE tenant_id=$1::uuid)`, id)
			check(e)
			_, e = p.Pool.Exec(cleanCtx, `DELETE FROM remnawave_imports WHERE tenant_id=$1::uuid`, id)
			check(e)
			_, e = p.Pool.Exec(cleanCtx, `DELETE FROM tenants WHERE id=$1::uuid`, id)
			check(e)
		}
	}()
	raw, err := os.ReadFile("../remnawave/testdata/inventory.json")
	check(err)
	_, report, err := remnawave.Parse(raw)
	check(err)
	if _, _, err = p.StageRemnawaveInventory(ctx, tenant.ID, raw, strings.Repeat("0", 64)); !errors.Is(err, ErrRemnawaveReview) {
		t.Fatal("unreviewed bytes admitted")
	}
	_, err = p.SetTenantResourceLimits(ctx, tenant.ID, 2, 0)
	check(err)
	if _, _, err = p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256); !errors.Is(err, ErrTenantQuota) {
		t.Fatal("batch exceeded target client quota")
	}
	clients, err := p.ListVPNClients(ctx, tenant.ID)
	check(err)
	if len(clients) != 0 {
		t.Fatal("partial import after quota rejection")
	}
	_, err = p.SetTenantResourceLimits(ctx, tenant.ID, 0, 0)
	check(err)
	for _, role := range []string{"admin", "monitor"} {
		scoped := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: role}})
		if _, _, err = p.StageRemnawaveInventory(scoped, tenant.ID, raw, report.SHA256); !errors.Is(err, ErrNotFound) {
			t.Fatal("non-owner staged credentials")
		}
	}
	scoped := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	if _, _, err = p.StageRemnawaveInventory(scoped, tenant.ID, raw, report.SHA256); !errors.Is(err, ErrNotFound) {
		t.Fatal("tenant staged credentials")
	}
	// Concurrent identical requests must create one batch and one client set.
	var wg sync.WaitGroup
	var mu sync.Mutex
	createdCount := 0
	ids := []string{}
	failures := []error{}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, created, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
			mu.Lock()
			defer mu.Unlock()
			if e != nil {
				failures = append(failures, e)
			}
			if created {
				createdCount++
			}
			ids = append(ids, v.ID)
		}()
	}
	wg.Wait()
	if len(failures) > 0 || createdCount != 1 || len(ids) != 3 || ids[0] != ids[1] || ids[1] != ids[2] {
		t.Fatalf("concurrent import not idempotent: failures=%d created=%d", len(failures), createdCount)
	}
	imported := ids[0]
	var preserved []byte
	check(p.Pool.QueryRow(ctx, `SELECT inventory FROM remnawave_imports WHERE id=$1::uuid`, imported).Scan(&preserved))
	if !bytes.Equal(raw, preserved) {
		t.Fatal("original credentials/metadata bytes changed")
	}
	clients, err = p.ListVPNClients(ctx, tenant.ID)
	check(err)
	if len(clients) != 3 {
		t.Fatal("wrong client count")
	}
	for _, client := range clients {
		if !client.RemnawaveHold || client.Status != "disabled" || client.EffectiveStatus != "disabled" {
			t.Fatal("staged client is not held")
		}
		if _, err = p.SetVPNClientStatus(ctx, client.ID, "active"); !errors.Is(err, ErrRemnawaveHold) {
			t.Fatal("normal enable bypassed migration hold")
		}
		if _, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='active' WHERE id=$1::uuid`, client.ID); err == nil {
			t.Fatal("database allowed held active client")
		}
		profiles, e := p.ListVPNClientConnections(ctx, client.ID)
		check(e)
		if len(profiles) != 0 {
			t.Fatal("held client received profiles")
		}
	}
	bindings, err := p.RemnawaveImportClients(ctx, imported, 0, 2)
	check(err)
	if len(bindings) != 2 || bindings[0].SourceID != 1 || bindings[1].SourceID != 2 {
		t.Fatal("source mapping/cursor lost")
	}
	tail, err := p.RemnawaveImportClients(ctx, imported, 2, 2)
	check(err)
	if len(tail) != 1 || tail[0].SourceID != 3 {
		t.Fatal("mapping pagination lost a user")
	}
	if _, _, err = p.StageRemnawaveInventory(ctx, other.ID, raw, report.SHA256); !errors.Is(err, ErrRemnawaveConflict) {
		t.Fatal("source reassigned to another tenant")
	}
	changed := append(append([]byte{}, raw...), byte('\n'))
	_, changedReport, e := remnawave.Parse(changed)
	check(e)
	if _, _, err = p.StageRemnawaveInventory(ctx, tenant.ID, changed, changedReport.SHA256); !errors.Is(err, ErrRemnawaveConflict) {
		t.Fatal("different source revision overwritten")
	}
	collision := bytes.Replace(raw, []byte("synthetic-remnawave.example.test"), []byte("second-source.example.test"), 1)
	_, collisionReport, e := remnawave.Parse(collision)
	check(e)
	if _, _, err = p.StageRemnawaveInventory(ctx, other.ID, collision, collisionReport.SHA256); !errors.Is(err, ErrRemnawaveConflict) {
		t.Fatal("existing VLESS identity silently changed or duplicated")
	}
	otherClients, e := p.ListVPNClients(ctx, other.ID)
	check(e)
	if len(otherClients) != 0 {
		t.Fatal("identity conflict committed partial clients")
	}
	imports, e := p.ListRemnawaveImports(ctx)
	check(e)
	if len(imports) != 1 {
		t.Fatal("rejected batch left import residue")
	}
	encoded, e := json.Marshal(imports)
	check(e)
	if bytes.Contains(encoded, []byte("synthetic-trojan")) || bytes.Contains(encoded, []byte("synthetic-source-subscription")) {
		t.Fatal("list response disclosed source credentials")
	}
	var auditCount int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND event_type='remnawave.inventory_staged'`, tenant.ID).Scan(&auditCount))
	if auditCount != 1 {
		t.Fatal("idempotent retries emitted duplicate import audit events")
	}
}
