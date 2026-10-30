//go:build integration

package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

// Opt-in harness for the unchanged Python commerce functions and real bot/CP
// PostgreSQL databases. Never included in the production control-plane binary.
func TestBotBridgePythonCommerceIntegration(t *testing.T) {
	dir := os.Getenv("VPN_BOT_COMMERCE_E2E_DIR")
	if dir == "" {
		t.Skip("separate Python commerce runner required")
	}
	if !strings.HasPrefix(dir, "/dev/shm/vpn-bot-db-r") || filepath.Clean(dir) != dir {
		t.Fatal("owned RAM directory required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	p, e := store.NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	check(e)
	defer p.Close()
	var database string
	check(p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database))
	if !strings.HasPrefix(database, "vpn_codex_test_delete_bot_") {
		t.Fatal("disposable CP database required")
	}
	tenant, e := p.CreateTenant(ctx, "Synthetic Python commerce")
	check(e)
	raw, e := os.ReadFile("../../internal/remnawave/testdata/inventory.json")
	check(e)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	inv["source_origin"] = "https://synthetic-python-commerce.example.test"
	for i, item := range inv["users"].([]any) {
		u := item.(map[string]any)
		u["trafficLimitStrategy"] = "NO_RESET"
		u["vlessUuid"] = []string{"e0000000-0000-4000-8000-", "e0000000-0000-4000-8001-", "e0000000-0000-4000-8002-"}[i] + tenant.ID[len(tenant.ID)-12:]
	}
	raw, e = json.Marshal(inv)
	check(e)
	_, report, e := remnawave.Parse(raw)
	check(e)
	imported, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(e)
	_, e = p.PrepareBotBridge(ctx, tenant.ID, imported.ID, report.SHA256)
	check(e)
	_, e = p.PrepareRemnawaveNoResetQuota(ctx, imported.ID, tenant.ID, report.SHA256)
	check(e)
	initial := time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Second)
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_clients SET remnawave_hold=false,status='active',expires_at=$2 WHERE tenant_id=$1::uuid`, tenant.ID, initial)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant.ID)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET baseline_bytes=12345,uplink_bytes=0,downlink_bytes=0,limit_bytes=0 WHERE client_id IN (SELECT client_id FROM bot_accounts WHERE tenant_id=$1::uuid)`, tenant.ID)
	check(e)
	_, _, e = p.ImportReviewedPPTP(ctx)
	check(e)
	check(p.ApproveReviewedPPTP(ctx))
	bootstrap := security.HashToken("synthetic-commerce-bootstrap")
	node, e := p.CreateNodeForRuntime(ctx, tenant.ID, "Synthetic commerce grant node", bootstrap, "pptp")
	check(e)
	_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-commerce-agent"), "0.2.30", "ubuntu", "24.04", "amd64", "pptp")
	check(e)
	_, _, e = p.InitializePPTPRuntime(ctx, node.ID)
	check(e)
	address, port := "synthetic-commerce.example.test", 1723
	service, e := p.CreateVPNService(ctx, node.ID, "Synthetic commerce service", "pptp", "0.0.0.0", port, "tcp,gre", "mppe", &address, &port)
	check(e)
	_, e = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(e)
	plan, e := p.CreateVPNAccessPlan(ctx, tenant.ID, "Synthetic source squad", "bot-source", true)
	check(e)
	_, e = p.SetVPNAccessPlanService(ctx, plan.ID, service.ID, true)
	check(e)
	var squad string
	check(p.Pool.QueryRow(ctx, `SELECT source_uuid::text FROM bot_squads WHERE tenant_id=$1::uuid`, tenant.ID).Scan(&squad))
	_, e = p.Pool.Exec(ctx, `UPDATE bot_squads SET plan_id=$2::uuid WHERE tenant_id=$1::uuid`, tenant.ID, plan.ID)
	check(e)
	random, e := security.NewToken(32)
	check(e)
	token := "vpt1_" + random
	_, e = p.CreateTenantAPIToken(ctx, tenant.ID, "synthetic-python", "operator", security.HashToken(token), time.Now().Add(time.Hour))
	check(e)
	app := &application{store: p}
	mux := http.NewServeMux()
	app.registerTenantAPIRoutes(mux)
	app.registerBotBridgeRoutes(mux)
	var guard sync.Mutex
	dropExtend, failPatch := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_synthetic/control" {
			if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "denied", 403)
				return
			}
			var command struct {
				DropExtend int `json:"drop_extend"`
				FailPatch  int `json:"fail_patch"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&command) != nil || command.DropExtend < 0 || command.DropExtend > 1 || command.FailPatch < 0 || command.FailPatch > 1 {
				http.Error(w, "invalid", 400)
				return
			}
			guard.Lock()
			dropExtend = command.DropExtend
			failPatch = command.FailPatch
			guard.Unlock()
			w.WriteHeader(204)
			return
		}
		guard.Lock()
		drop := r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/actions/extend") && dropExtend > 0
		fail := r.Method == "PATCH" && r.URL.Path == "/api/v1/tenant/bot/users" && failPatch > 0
		if drop {
			dropExtend--
		}
		if fail {
			failPatch--
		}
		guard.Unlock()
		if fail {
			http.Error(w, "synthetic transient failure", 503)
			return
		}
		if drop {
			captured := httptest.NewRecorder()
			mux.ServeHTTP(captured, r)
			if captured.Code != 200 {
				t.Errorf("real extension handler failed before disconnect: HTTP%d", captured.Code)
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	check(os.WriteFile(filepath.Join(dir, "commerce-ca.pem"), cert, 0600))
	descriptor := map[string]any{"origin": server.URL, "token": token, "tenant_id": tenant.ID, "squad": squad, "initial_expiry": initial, "legacy_ids": []int{1, 2}, "readiness_expected": false}
	raw, e = json.Marshal(descriptor)
	check(e)
	check(os.WriteFile(filepath.Join(dir, "commerce-ready.tmp"), raw, 0600))
	check(os.Rename(filepath.Join(dir, "commerce-ready.tmp"), filepath.Join(dir, "commerce-ready.json")))
	for {
		if raw, e = os.ReadFile(filepath.Join(dir, "commerce-done.json")); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("Python commerce completion deadline")
		case <-time.After(200 * time.Millisecond):
		}
	}
	var result struct {
		Status string `json:"status"`
	}
	check(json.Unmarshal(raw, &result))
	if result.Status != "PASS" {
		t.Fatal("Python commerce failed")
	}
	// Two independent extensions plus a retry after a failed patch must apply
	// exactly three times to each existing account. Read directly from native PG.
	for _, id := range []int{1, 2} {
		var expiry time.Time
		var used, grants int64
		check(p.Pool.QueryRow(ctx, `SELECT c.expires_at,q.baseline_bytes+q.uplink_bytes+q.downlink_bytes,
   (SELECT count(*) FROM vpn_effective_client_services e WHERE e.client_id=c.id)
   FROM bot_accounts b JOIN vpn_clients c ON c.id=b.client_id JOIN vpn_client_continuous_quotas q ON q.client_id=c.id
   WHERE b.tenant_id=$1::uuid AND b.legacy_id=$2`, tenant.ID, id).Scan(&expiry, &used, &grants))
		if expiry.Sub(initial) != 90*24*time.Hour || used != 12345 || grants != 1 {
			t.Fatal("native commerce expiry/quota/grant mismatch")
		}
	}
	var nativeCount int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_accounts WHERE tenant_id=$1::uuid AND legacy_id>=4503599627370496 AND legacy_id<=9007199254740991 AND deleted_at IS NULL`, tenant.ID).Scan(&nativeCount))
	if nativeCount != 2 {
		t.Fatal("new paid account count mismatch")
	}
	proof := map[string]any{"status": "PASS", "real_https": true, "real_bot_postgres": true, "real_cp_postgres": true, "lost_reply_after_commit": true, "existing_accounts": 2, "new_native_accounts": nativeCount, "expiry_delta_days_per_account": 90, "no_reset_bytes_per_account": 12345, "readiness_still_fenced": true}
	raw, e = json.Marshal(proof)
	check(e)
	check(os.WriteFile(filepath.Join(dir, "commerce-proof.json"), raw, 0600))
}
