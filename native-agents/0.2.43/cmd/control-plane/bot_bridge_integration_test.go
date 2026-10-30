//go:build integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestBotBridgeHTTPIsolationIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p, e := store.NewPostgres(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var database string
	check(p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database))
	if !strings.HasPrefix(database, "vpn_codex_test_delete_bot_") {
		t.Fatal("dedicated disposable bot DB required")
	}
	tenant, e := p.CreateTenant(ctx, "HTTP bot tenant")
	check(e)
	foreign, e := p.CreateTenant(ctx, "HTTP foreign bot tenant")
	check(e)
	raw, e := os.ReadFile("../../internal/remnawave/testdata/inventory.json")
	check(e)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	inv["source_origin"] = "https://synthetic-http-bot.example.test"
	for i, v := range inv["users"].([]any) {
		v.(map[string]any)["trafficLimitStrategy"] = "NO_RESET"
		v.(map[string]any)["vlessUuid"] = []string{"d0000000-0000-4000-8000-", "d0000000-0000-4000-8001-", "d0000000-0000-4000-8002-"}[i] + tenant.ID[len(tenant.ID)-12:]
	}
	inv["users"].([]any)[0].(map[string]any)["telegramId"] = float64(123456789)
	raw, e = json.Marshal(inv)
	check(e)
	_, report, e := remnawave.Parse(raw)
	check(e)
	imported, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(e)
	_, e = p.PrepareBotBridge(ctx, tenant.ID, imported.ID, report.SHA256)
	check(e)
	tokens := map[string]string{}
	for _, item := range []struct{ name, tenant, role string }{{"operator", tenant.ID, "operator"}, {"viewer", tenant.ID, "viewer"}, {"foreign", foreign.ID, "operator"}, {"reseller", tenant.ID, "reseller"}} {
		random, e := security.NewToken(32)
		check(e)
		tokens[item.name] = "vpt1_" + random
		_, e = p.CreateTenantAPIToken(ctx, item.tenant, item.name, item.role, security.HashToken(tokens[item.name]), time.Now().Add(time.Hour))
		check(e)
	}
	app := &application{store: p, adminToken: "synthetic-root-not-accepted-by-bot"}
	mux := http.NewServeMux()
	app.registerTenantAPIRoutes(mux)
	app.registerBotBridgeRoutes(mux)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Synthetic-Drop-Response") == "1" {
			captured := httptest.NewRecorder()
			mux.ServeHTTP(captured, r)
			// Commit has completed in the real handler. Close the HTTP connection before
			// returning a single response byte, as in a management transport interruption.
			connection, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				connection.Close()
			}
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()
	request := func(role, path string, want int) []byte {
		t.Helper()
		req, e := http.NewRequest("GET", server.URL+"/api/v1/tenant/bot"+path, nil)
		check(e)
		if role == "root" {
			req.Header.Set("Authorization", "Bearer "+app.adminToken)
		} else if role != "" {
			req.Header.Set("Authorization", "Bearer "+tokens[role])
		}
		res, e := server.Client().Do(req)
		check(e)
		defer res.Body.Close()
		body, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		check(e)
		if res.StatusCode != want {
			t.Fatalf("bot HTTP %s %s: got %d expected %d", role, path, res.StatusCode, want)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("credential-bearing response cacheable")
		}
		for _, secret := range []string{"vlessUuid", "trojanPassword", "ssPassword", "synthetic-trojan", "synthetic-ss", "unmappedCustomMetadata", "synthetic-root-not-accepted-by-bot"} {
			if strings.Contains(string(body), secret) {
				t.Fatal("source secret exposed")
			}
		}
		for _, secret := range tokens {
			if strings.Contains(string(body), secret) {
				t.Fatal("tenant token echoed")
			}
		}
		return body
	}
	for _, r := range []struct {
		role   string
		status int
	}{{"", 401}, {"root", 401}, {"viewer", 403}, {"reseller", 403}} {
		request(r.role, "/users/1", r.status)
	}
	request("operator", "/users/1", 409)
	request("operator", "/users/stream", 409)
	request("operator", "/hwid/devices/1", 409)
	var status store.BotStatus
	check(json.Unmarshal(request("operator", "/status", 200), &status))
	if status.State != "held" || status.MigrationReady || status.TenantID != tenant.ID {
		t.Fatal("held readiness contract")
	}
	_, e = p.PrepareRemnawaveNoResetQuota(ctx, imported.ID, tenant.ID, report.SHA256)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_clients SET remnawave_hold=false,status='active' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant.ID)
	check(e)
	body := request("operator", "/users/1", 200)
	var user struct {
		Response struct {
			ID              int64
			Username        string
			TelegramID      int64
			SubscriptionURL string
		}
	}
	check(json.Unmarshal(body, &user))
	if user.Response.ID != 1 || user.Response.TelegramID != 123456789 || !strings.HasPrefix(user.Response.SubscriptionURL, "https://subscriptions.example.test/") {
		t.Fatal("HTTP numeric identity/subscription projection")
	}
	request("operator", "/users/by-username/"+user.Response.Username, 200)
	request("operator", "/subscriptions/by-id/1", 200)
	request("operator", "/hwid/devices/1", 200)
	request("operator", "/users/999", 404)
	request("foreign", "/users/1", 409)
	for _, q := range []string{"?size=0", "?size=1001", "?size=1&size=2", "?cursor=-1", "?cursor=9007199254740992", "?telegramId=abc", "?unknown=1", "?email=%ZZ", "?email=x;y"} {
		request("operator", "/users/stream"+q, 400)
	}
	for _, id := range []string{"0", "01", "+1", "-1", "9007199254740992"} {
		request("operator", "/users/"+id, 400)
	}
	page := request("operator", "/users/stream?size=1&telegramId=123456789", 200)
	var users struct {
		Response struct {
			Users      []json.RawMessage
			NextCursor *int64
		}
	}
	check(json.Unmarshal(page, &users))
	if len(users.Response.Users) != 1 || users.Response.NextCursor != nil {
		t.Fatal("HTTP exact filter/pagination")
	}
	mutation := func(method, path, body, key, role string, drop bool, want int) []byte {
		t.Helper()
		req, e := http.NewRequest(method, server.URL+"/api/v1/tenant/bot"+path, strings.NewReader(body))
		check(e)
		req.Header.Set("Authorization", "Bearer "+tokens[role])
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		if drop {
			req.Header.Set("X-Synthetic-Drop-Response", "1")
		}
		res, e := server.Client().Do(req)
		if drop {
			if e == nil {
				res.Body.Close()
				t.Fatal("synthetic lost response was delivered")
			}
			return nil
		}
		check(e)
		defer res.Body.Close()
		raw, e := io.ReadAll(res.Body)
		check(e)
		if res.StatusCode != want {
			t.Fatalf("mutation %s %s HTTP %d expected %d", method, path, res.StatusCode, want)
		}
		return raw
	}
	var clientID string
	var before, after time.Time
	check(p.Pool.QueryRow(ctx, `SELECT c.id::text,c.expires_at FROM bot_accounts b JOIN vpn_clients c ON c.id=b.client_id WHERE b.tenant_id=$1::uuid AND b.legacy_id=1`, tenant.ID).Scan(&clientID, &before))
	// Fix a future expiry to isolate arithmetic from an already expired fixture.
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()+interval '7 days' WHERE id=$1::uuid`, clientID)
	check(e)
	check(p.Pool.QueryRow(ctx, `SELECT expires_at FROM vpn_clients WHERE id=$1::uuid`, clientID).Scan(&before))
	key := strings.Repeat("a", 64)
	mutation("POST", "/users/1/actions/extend", `{"days":30}`, key, "operator", true, 0)
	mutation("POST", "/users/1/actions/extend", `{"days":30}`, key, "operator", false, 200)
	check(p.Pool.QueryRow(ctx, `SELECT expires_at FROM vpn_clients WHERE id=$1::uuid`, clientID).Scan(&after))
	if after.Sub(before) != 30*24*time.Hour {
		t.Fatal("lost HTTP response duplicated extension")
	}
	mutation("POST", "/users/2/actions/extend", `{"days":30}`, key, "operator", false, 409)
	mutation("POST", "/users/1/actions/extend", `{"days":31}`, key, "operator", false, 409)
	mutation("POST", "/users/1/actions/extend", `{"days":30}`, "", "operator", false, 400)
	mutation("POST", "/users/1/actions/extend", `{"days":30,"days":31}`, strings.Repeat("b", 64), "operator", false, 400)
	mutation("POST", "/users/1/actions/extend", `{"days":30,"Days":31}`, strings.Repeat("b", 64), "operator", false, 400)
	mutation("POST", "/users/1/actions/extend", `{"days":null}`, strings.Repeat("b", 64), "operator", false, 400)
	mutation("POST", "/users/1/actions/extend", `{"days":30}`, strings.Repeat("b", 64), "viewer", false, 403)
	mutation("POST", "/users/1/actions/disable", "", strings.Repeat("c", 64), "operator", false, 200)
	mutation("POST", "/users/1/actions/enable", "", strings.Repeat("d", 64), "operator", false, 200)
	mutation("POST", "/users/1/actions/reset-traffic", "", strings.Repeat("e", 64), "operator", false, 200)
	mutation("POST", "/hwid/devices/delete-all", `{"userId":1}`, strings.Repeat("f", 64), "operator", false, 200)
	mutation("DELETE", "/users/1", "", strings.Repeat("1", 64), "operator", false, 200)
	mutation("DELETE", "/users/1", "", strings.Repeat("1", 64), "operator", false, 200)
	request("operator", "/users/1", 404)
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(e)
	request("operator", "/users/1", 409)
}
