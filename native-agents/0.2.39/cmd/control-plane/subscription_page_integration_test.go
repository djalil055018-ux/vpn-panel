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
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func TestPublicSubscriptionPageIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	p, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("database unavailable")
	}
	defer p.Close()
	var database string
	if p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&database) != nil || !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "Subscription page fixture")
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "Synthetic account", nil)
	check(err)
	key := bytes.Repeat([]byte{71}, 32)
	t.Setenv("SUBSCRIPTION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(key))
	id, err := newSubscriptionTokenID()
	check(err)
	token, hash, err := buildSubscriptionToken(key, id, 1)
	check(err)
	_, err = p.CreateVPNClientSubscription(ctx, client.ID, id, 1, hash, "fixture")
	check(err)
	app := &application{store: p}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sub/{token}/info", app.getPublicSubscriptionInfo)
	mux.HandleFunc("GET /sub/{token}", app.getPublicVPNSubscription)
	request := func(path string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("X-Hwid", "FixtureMustNotRegister")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("response status %d want %d", w.Code, want)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("private response headers missing")
		}
		return w
	}
	page := func(want string) store.PublicSubscriptionInfo {
		t.Helper()
		w := request("/sub/"+token+"/info", 200)
		var info store.PublicSubscriptionInfo
		check(json.Unmarshal(w.Body.Bytes(), &info))
		if info.Status != want || info.Name != client.Name || info.Brand != "PAUK" {
			t.Fatal("metadata state mismatch")
		}
		for _, secret := range []string{client.ID, client.VLESSUUID, tenant.ID, token, "FixtureMustNotRegister", "vless_uuid", "token_hash"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("private material disclosed")
			}
		}
		return info
	}
	if page("active").AutoProfile != nil {
		t.Fatal("disabled Auto exposed")
	}
	_, err = p.SetAutoProfileSettings(ctx, tenant.ID, model.AutoProfileSettings{Enabled: true, Name: "Мой маршрут", RussiaDirect: true})
	check(err)
	publicAuto := page("active").AutoProfile
	if publicAuto == nil || publicAuto.Name != "Мой маршрут" || !publicAuto.RussiaDirect {
		t.Fatal("Auto display metadata absent")
	}
	_, err = p.SetAutoProfileSettings(ctx, tenant.ID, model.AutoProfileSettings{Enabled: false, Name: "Мой маршрут", RussiaDirect: true})
	check(err)
	if page("active").AutoProfile != nil {
		t.Fatal("disabled Auto retained")
	}
	foreign, err := p.CreateTenant(ctx, "Other subscription page tenant")
	check(err)
	_, err = p.Pool.Exec(ctx, "UPDATE vpn_client_subscriptions SET tenant_id=$2::uuid WHERE client_id=$1::uuid", client.ID, foreign.ID)
	check(err)
	request("/sub/"+token+"/info", 404)
	_, err = p.Pool.Exec(ctx, "UPDATE vpn_client_subscriptions SET tenant_id=$2::uuid WHERE client_id=$1::uuid", client.ID, tenant.ID)
	check(err)
	_, err = p.SetRegisteredDeviceLimit(ctx, client.ID, 2)
	check(err)
	info := page("active")
	if info.DeviceLimit != 2 || info.DeviceCount != 0 {
		t.Fatal("device metadata mismatch")
	}
	var accesses, devices int
	check(p.Pool.QueryRow(ctx, "SELECT count(*) FROM vpn_client_subscriptions WHERE client_id=$1::uuid AND last_access_at IS NOT NULL", client.ID).Scan(&accesses))
	check(p.Pool.QueryRow(ctx, "SELECT count(*) FROM bot_devices WHERE client_id=$1::uuid", client.ID).Scan(&devices))
	if accesses != 0 || devices != 0 {
		t.Fatal("metadata fetch mutated subscription or devices")
	}
	// Browser metadata must never weaken the independent raw subscription admission gate.
	r := httptest.NewRequest("GET", "/sub/"+token, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 404 || w.Header().Get("X-Hwid-Not-Supported") != "true" {
		t.Fatal("raw device gate bypassed")
	}
	exec := func(sql string) { t.Helper(); _, err := p.Pool.Exec(ctx, sql, client.ID); check(err) }
	exec("UPDATE vpn_clients SET expires_at=now()-interval '1 day' WHERE id=$1::uuid")
	page("expired")
	exec("UPDATE vpn_clients SET status='disabled' WHERE id=$1::uuid")
	page("disabled")
	exec("UPDATE vpn_clients SET status='active',expires_at=NULL WHERE id=$1::uuid")
	exec("INSERT INTO vpn_client_limits(client_id,monthly_bytes) VALUES($1::uuid,100)")
	exec("INSERT INTO vpn_client_usage_monthly(client_id,period_start,uplink_bytes,downlink_bytes) VALUES($1::uuid,date_trunc('month',now() AT TIME ZONE 'UTC')::date,30,80)")
	info = page("quota_exceeded")
	if info.UsedBytes != 110 || info.LimitBytes != 100 || info.ResetPolicy != "MONTH" {
		t.Fatal("traffic metadata mismatch")
	}
	exec("UPDATE vpn_clients SET status='disabled',remnawave_hold=true WHERE id=$1::uuid")
	request("/sub/"+token+"/info", 404)
	exec("UPDATE vpn_clients SET status='active',remnawave_hold=false WHERE id=$1::uuid")
	_, nextHash, err := buildSubscriptionToken(key, id, 2)
	check(err)
	_, err = p.RotateVPNClientSubscription(ctx, client.ID, 1, 2, nextHash, "new-fixture")
	check(err)
	request("/sub/"+token+"/info", 404)
	token, _, err = buildSubscriptionToken(key, id, 2)
	check(err)
	page("quota_exceeded")
	exec("UPDATE vpn_client_subscriptions SET status='revoked' WHERE client_id=$1::uuid")
	request("/sub/"+token+"/info", 404)
	request("/sub/invalid/info", 404)
}
