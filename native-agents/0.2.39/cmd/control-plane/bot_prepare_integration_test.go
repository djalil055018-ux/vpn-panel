//go:build integration

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/store"
)

func TestBotPreparationHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	p, e := store.NewPostgres(ctx, dsn)
	check(e)
	defer p.Close()
	var database string
	check(p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database))
	if !strings.HasPrefix(database, "vpn_codex_test_delete_bot_") {
		t.Fatal("dedicated disposable DB required")
	}
	tenant, e := p.CreateTenant(ctx, "Bot owner preparation HTTP")
	check(e)
	foreign, e := p.CreateTenant(ctx, "Bot preparation foreign")
	check(e)
	raw, e := os.ReadFile("../../internal/remnawave/testdata/inventory.json")
	check(e)
	var source map[string]any
	check(json.Unmarshal(raw, &source))
	source["source_origin"] = "https://bot-preparation-http.example.test"
	for i, v := range source["users"].([]any) {
		u := v.(map[string]any)
		u["trafficLimitStrategy"] = "NO_RESET"
		u["shortUuid"] = "bot-prepare-http-" + string(rune('a'+i))
		u["subscriptionUrl"] = "https://subscriptions.example.test/" + u["shortUuid"].(string)
		u["vlessUuid"] = []string{"f0000000-0000-4000-8000-", "f0000000-0000-4000-8001-", "f0000000-0000-4000-8002-"}[i] + tenant.ID[len(tenant.ID)-12:]
	}
	raw, e = json.Marshal(source)
	check(e)
	_, review, e := remnawave.Parse(raw)
	check(e)
	imported, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, review.SHA256)
	check(e)
	app := &application{store: p, adminToken: "synthetic-prepare-owner"}
	mux := http.NewServeMux()
	app.registerRemnawaveRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	call := func(tid, digest string, want int) store.BotPreparation {
		t.Helper()
		req, e := http.NewRequest("POST", server.URL+"/api/v1/remnawave/imports/"+imported.ID+"/prepare-bot", strings.NewReader(`{"tenant_id":"`+tid+`"}`))
		check(e)
		req.Header.Set("Authorization", "Bearer "+app.adminToken)
		req.Header.Set("X-Remnawave-Mode", "prepare-held-bot")
		req.Header.Set("X-Reviewed-Inventory-SHA256", digest)
		res, e := server.Client().Do(req)
		check(e)
		defer res.Body.Close()
		body, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		check(e)
		if res.StatusCode != want || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("preparation status/cache contract")
		}
		for _, secret := range []string{"vlessUuid", "trojanPassword", "ssPassword", "unmappedCustomMetadata", app.adminToken} {
			if strings.Contains(string(body), secret) {
				t.Fatal("private preparation source leaked")
			}
		}
		var out store.BotPreparation
		if want == 200 {
			check(json.Unmarshal(body, &out))
		}
		return out
	}
	call(foreign.ID, review.SHA256, 404)
	call(tenant.ID, strings.Repeat("0", 64), 400)
	var profiles int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_profiles WHERE tenant_id=$1::uuid`, tenant.ID).Scan(&profiles))
	if profiles != 0 {
		t.Fatal("denial persisted bot profile")
	}
	first := call(tenant.ID, review.SHA256, 200)
	again := call(tenant.ID, review.SHA256, 200)
	if !reflect.DeepEqual(first, again) || first.Users != 3 || first.MigrationReady || first.InventorySHA256 != review.SHA256 {
		t.Fatal("held preparation/retry contract")
	}
	var held, grants, subscriptions, generations int
	check(p.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM vpn_clients WHERE tenant_id=$1::uuid AND remnawave_hold AND status='disabled'),(SELECT count(*) FROM vpn_effective_client_services WHERE tenant_id=$1::uuid),(SELECT count(*) FROM vpn_client_subscriptions WHERE tenant_id=$1::uuid),(SELECT count(*) FROM desired_states d JOIN nodes n ON n.id=d.node_id WHERE n.tenant_id=$1::uuid)`, tenant.ID).Scan(&held, &grants, &subscriptions, &generations))
	if held != 3 || grants != 0 || subscriptions != 0 || generations != 0 {
		t.Fatal("preparation activated native access")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(e)
	call(tenant.ID, review.SHA256, 409)
}
