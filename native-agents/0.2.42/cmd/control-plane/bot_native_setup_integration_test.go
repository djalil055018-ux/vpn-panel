//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestNativeBotFreshInstallIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	p, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal("disposable database required")
	}
	tenant, err := p.CreateTenant(ctx, "Fresh standalone commerce")
	check(err)
	foreign, err := p.CreateTenant(ctx, "Foreign standalone commerce")
	check(err)
	plan, err := p.CreateVPNAccessPlan(ctx, tenant.ID, "Основная", "native-bot", true)
	check(err)
	otherPlan, err := p.CreateVPNAccessPlan(ctx, foreign.ID, "Foreign", "native-bot", true)
	check(err)
	token := "vpt1_" + strings.Repeat("x", 43)
	_, err = p.CreateTenantAPIToken(ctx, tenant.ID, "fresh-bot", "operator", security.HashToken(token), time.Now().Add(time.Hour))
	check(err)
	app := &application{store: p, adminToken: "fixture-root"}
	mux := http.NewServeMux()
	app.registerTenantAPIRoutes(mux)
	app.registerBotBridgeRoutes(mux)
	mux.HandleFunc("GET /sub/{token}", app.getPublicVPNSubscription)
	mux.HandleFunc("GET /api/v1/public/subscriptions/{token}/info", app.getPublicSubscriptionInfo)
	request := func(method, path, auth string, body any, headers map[string]string, want int) *httptest.ResponseRecorder {
		t.Helper()
		raw, e := json.Marshal(body)
		check(e)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s route: got %d want %d; %s", method, w.Code, want, w.Body.String())
		}
		return w
	}
	setupPath := "/api/v1/tenants/" + tenant.ID + "/bot/native"
	setup := map[string]string{"subscription_base": "https://fresh.example.test/sub/", "access_plan_id": plan.ID}
	request("POST", setupPath, "", setup, nil, 401)
	request("POST", setupPath, token, setup, nil, 401)
	request("POST", setupPath, "fixture-root", map[string]string{"subscription_base": setup["subscription_base"], "access_plan_id": otherPlan.ID}, nil, 404)
	request("POST", setupPath, "fixture-root", map[string]string{"subscription_base": "http://fresh.example.test/sub/", "access_plan_id": plan.ID}, nil, 400)
	request("POST", setupPath, "fixture-root", map[string]string{"subscription_base": setup["subscription_base"], "access_plan_id": plan.ID, "extra": "denied"}, nil, 400)
	request("POST", setupPath, "fixture-root", setup, nil, 200)
	request("POST", setupPath, "fixture-root", setup, nil, 200)
	request("POST", setupPath, "fixture-root", map[string]string{"subscription_base": "https://changed.example.test/sub/", "access_plan_id": plan.ID}, nil, 409)
	var imports, events int
	check(p.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM remnawave_imports WHERE tenant_id=$1::uuid),(SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND event_type='bot_bridge.native_configured')`, tenant.ID).Scan(&imports, &events))
	if imports != 0 || events != 1 {
		t.Fatal("fresh setup fabricated migration or replayed mutation")
	}
	status := request("GET", "/api/v1/tenant/bot/status", token, nil, nil, 200)
	var ready store.BotStatus
	check(json.Unmarshal(status.Body.Bytes(), &ready))
	if !ready.MigrationReady || ready.State != "active" {
		t.Fatal("fresh bot unavailable")
	}
	// A plan must actually contain an enabled service before a customer can buy it.
	create := store.BotCreateInput{Username: "fresh_customer", DurationDays: 30, TrafficLimitStrategy: "NO_RESET", HWIDDeviceLimit: 1, ActiveInternalSquads: []string{plan.ID}}
	key := map[string]string{"Idempotency-Key": strings.Repeat("a", 64)}
	request("POST", "/api/v1/tenant/bot/users", token, create, key, 409)
	release, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.9.9", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/xray.zip", SHA256: strings.Repeat("a", 64), Channel: "testing"})
	check(err)
	check(p.ApproveCoreRelease(ctx, release.ID))
	bootstrap := security.HashToken("native-fresh-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "Fresh native node", bootstrap, "xray")
	check(err)
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("native-fresh-agent"), "0.2.34", "ubuntu", "24.04", "amd64", "xray")
	check(err)
	check(p.SaveDesiredState(ctx, node.ID, model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: release.Type, Version: release.Version, DownloadURL: release.DownloadURL, SHA256: release.SHA256, Channel: release.Channel}}, release.ID))
	address, port := "native.example.test", 19443
	service, err := p.CreateVPNService(ctx, node.ID, "Fresh VLESS", "vless", "0.0.0.0", port, "tcp", "reality", &address, &port)
	check(err)
	_, err = p.ConfigureVPNServiceReality(ctx, service.ID, "example.test:443", "example.test", "firefox", "0123456789abcdef")
	check(err)
	// This disposable fixture has no real agent to publish its generated public key.
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_service_reality SET public_key='BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc' WHERE service_id=$1::uuid`, service.ID)
	check(err)
	_, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(err)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service.ID, true)
	check(err)
	w := request("POST", "/api/v1/tenant/bot/users", token, create, key, 201)
	var created struct {
		Response struct {
			ID              int64
			ShortUUID       string
			SubscriptionURL string
			ExpireAt        time.Time
		}
	}
	check(json.Unmarshal(w.Body.Bytes(), &created))
	id := created.Response.ID
	alias := created.Response.ShortUUID
	if id != 4503599627370496 || created.Response.SubscriptionURL != setup["subscription_base"]+alias {
		t.Fatal("native identity or canonical URL mismatch")
	}
	again := request("POST", "/api/v1/tenant/bot/users", token, create, key, 201)
	var replay struct {
		Response struct {
			ID       int64
			ExpireAt time.Time
		}
	}
	check(json.Unmarshal(again.Body.Bytes(), &replay))
	if replay.Response.ID != id || !replay.Response.ExpireAt.Equal(created.Response.ExpireAt) {
		t.Fatal("create retry duplicated subscription")
	}
	clientID, err := p.ResolveNativeBotAlias(ctx, alias)
	check(err)
	connections, err := p.ListVPNClientConnections(ctx, clientID)
	check(err)
	if len(connections) != 1 || connections[0].ServiceID != service.ID {
		t.Fatal("Main access not granted")
	}
	info := request("GET", "/api/v1/public/subscriptions/"+alias+"/info", "", nil, nil, 200)
	if strings.Contains(info.Body.String(), connections[0].UUID) {
		t.Fatal("metadata leaked VPN credential")
	}
	devices, err := p.RegisteredDevices(ctx, clientID)
	check(err)
	if devices.Count != 0 || devices.Limit != 1 {
		t.Fatal("metadata registered device or lost cap")
	}
	path := "/sub/" + alias
	request("GET", path, "", nil, nil, 404)
	raw := request("GET", path, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceOne"}, 200)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw.Body.String()))
	check(err)
	if !strings.Contains(string(decoded), "vless://") || !strings.Contains(string(decoded), address) {
		t.Fatal("native subscription missing connection")
	}
	request("GET", path, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceTwo"}, 404)
	// An additional paid slot and the owner's cap address exactly the same registry.
	request("PATCH", "/api/v1/tenant/bot/users", token, map[string]any{"id": id, "hwidDeviceLimit": 2}, map[string]string{"Idempotency-Key": strings.Repeat("d", 64)}, 200)
	request("GET", path, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceTwo"}, 200)
	request("GET", path, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceThree"}, 404)
	request("PATCH", "/api/v1/tenant/bot/users", token, map[string]any{"id": id, "hwidDeviceLimit": 1}, map[string]string{"Idempotency-Key": strings.Repeat("e", 64)}, 409)
	devices, err = p.SetRegisteredDeviceLimit(ctx, clientID, 3)
	check(err)
	if devices.Limit != 3 || devices.Count != 2 {
		t.Fatal("owner cap and registry differ")
	}
	user := request("GET", fmt.Sprintf("/api/v1/tenant/bot/users/%d", id), token, nil, nil, 200)
	var updated struct {
		Response struct {
			Limit int `json:"hwidDeviceLimit"`
		}
	}
	check(json.Unmarshal(user.Body.Bytes(), &updated))
	if updated.Response.Limit != 3 {
		t.Fatal("bot did not observe owner cap")
	}
	// Expired and disabled subscriptions cannot fetch even a previously bound profile.
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()-interval '1 second' WHERE id=$1::uuid`, clientID)
	check(err)
	request("GET", path, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceOne"}, 404)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()+interval '30 days',status='disabled' WHERE id=$1::uuid`, clientID)
	check(err)
	request("GET", path, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceOne"}, 404)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='active' WHERE id=$1::uuid`, clientID)
	check(err)
	operator := store.WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	foreignOperator := store.WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"})
	if _, err = p.ResolveNativeBotAlias(foreignOperator, alias); err != store.ErrNotFound {
		t.Fatal("foreign tenant resolved alias")
	}
	if _, err = p.ConfigureNativeBot(operator, tenant.ID, setup["subscription_base"], plan.ID); err != store.ErrNotFound {
		t.Fatal("tenant operator configured owner integration")
	}
	// Native signed links for a bot customer must also retain the native renderer.
	signing := bytes.Repeat([]byte{81}, 32)
	t.Setenv("SUBSCRIPTION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(signing))
	tid, err := newSubscriptionTokenID()
	check(err)
	signed, hash, err := buildSubscriptionToken(signing, tid, 1)
	check(err)
	_, err = p.CreateVPNClientSubscription(ctx, clientID, tid, 1, hash, "native bot test")
	check(err)
	request("GET", "/sub/"+signed, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceOne"}, 200)
	// Pause blocks commerce while preserving an existing subscriber's connection.
	_, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(err)
	request("POST", fmt.Sprintf("/api/v1/tenant/bot/users/%d/actions/extend", id), token, map[string]int{"days": 30}, map[string]string{"Idempotency-Key": strings.Repeat("b", 64)}, 409)
	request("GET", path, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceOne"}, 200)
	_, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(err)
	request("POST", fmt.Sprintf("/api/v1/tenant/bot/users/%d/actions/revoke", id), token, map[string]any{}, map[string]string{"Idempotency-Key": strings.Repeat("c", 64)}, 200)
	request("GET", path, "", nil, map[string]string{"X-Hwid": "FreshNativeDeviceOne"}, 404)
	request("GET", "/api/v1/public/subscriptions/"+alias+"/info", "", nil, nil, 404)
	// The bot contract exposes link rotation and device removal as separate actions.
	// A revoked alias must not add a new device before the explicit removal.
	devices, err = p.RegisteredDevices(ctx, clientID)
	check(err)
	if devices.Count != 2 {
		t.Fatal("revoked alias changed device registry")
	}
	request("POST", "/api/v1/tenant/bot/hwid/devices/delete-all", token, map[string]any{"userId": id}, map[string]string{"Idempotency-Key": strings.Repeat("f", 64)}, 200)
	devices, err = p.RegisteredDevices(ctx, clientID)
	check(err)
	if devices.Count != 0 {
		t.Fatal("explicit removal retained bound devices")
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET profile_kind='imported' WHERE tenant_id=$1::uuid`, tenant.ID); err == nil {
		t.Fatal("profile origin conversion allowed")
	}
}
