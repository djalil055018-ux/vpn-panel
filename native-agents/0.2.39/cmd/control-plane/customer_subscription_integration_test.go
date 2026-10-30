//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestCustomerSubscriptionHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	p, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var database string
	check(p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&database))
	if !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("disposable database required")
	}
	tenant, err := p.CreateTenant(ctx, "Customer HTTP tenant")
	check(err)
	foreign, err := p.CreateTenant(ctx, "Foreign customer HTTP tenant")
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "Synthetic personal subscription", nil)
	check(err)
	signing := bytes.Repeat([]byte{19}, 32)
	t.Setenv("SUBSCRIPTION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(signing))
	id, err := newSubscriptionTokenID()
	check(err)
	token, hash, err := buildSubscriptionToken(signing, id, 1)
	check(err)
	_, err = p.CreateVPNClientSubscription(ctx, client.ID, id, 1, hash, "synthetic")
	check(err)
	tokens := map[string]string{"root": "synthetic-root"}
	for _, v := range []struct{ name, tenant, role string }{{"operator", tenant.ID, "operator"}, {"viewer", tenant.ID, "viewer"}, {"reseller", tenant.ID, "reseller"}, {"foreign", foreign.ID, "operator"}} {
		random, e := security.NewToken(32)
		check(e)
		tokens[v.name] = "vpt1_" + random
		_, e = p.CreateTenantAPIToken(ctx, v.tenant, v.name, v.role, security.HashToken(tokens[v.name]), time.Now().Add(time.Hour))
		check(e)
	}
	app := &application{store: p, adminToken: tokens["root"]}
	mux := http.NewServeMux()
	app.registerBotBridgeRoutes(mux)
	request := func(role, path string, body any, want int) *httptest.ResponseRecorder {
		t.Helper()
		raw, e := json.Marshal(body)
		check(e)
		r := httptest.NewRequest("POST", "/api/v1/tenant/bot/"+path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if role != "" {
			r.Header.Set("Authorization", "Bearer "+tokens[role])
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: got %d want %d", role, path, w.Code, want)
		}
		if strings.Contains(w.Body.String(), client.VLESSUUID) || strings.Contains(w.Body.String(), token) {
			t.Fatal("credential disclosed")
		}
		return w
	}
	body := map[string]any{"subscription_token": token}
	for _, v := range []struct {
		role   string
		status int
	}{{"", 401}, {"root", 401}, {"viewer", 403}, {"reseller", 403}, {"foreign", 404}, {"operator", 200}} {
		request(v.role, "customer-context", body, v.status)
	}
	request("operator", "customer-context", map[string]any{"subscription_token": token, "client_id": client.ID}, 400)
	request("operator", "customer-context", map[string]any{"subscription_token": "invalid"}, 400)
	request("operator", "customer-devices", map[string]any{"subscription_token": token, "action": "list"}, 200)
	request("foreign", "customer-devices", map[string]any{"subscription_token": token, "action": "list"}, 404)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_client_subscriptions SET status='revoked' WHERE client_id=$1::uuid`, client.ID)
	check(err)
	request("operator", "customer-context", body, 404)
	request("operator", "customer-devices", map[string]any{"subscription_token": token, "action": "list"}, 404)
}
