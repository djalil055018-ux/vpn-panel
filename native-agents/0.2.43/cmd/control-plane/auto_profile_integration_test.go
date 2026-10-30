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
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestAutoProfileHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	p, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("database unavailable")
	}
	defer p.Close()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var database string
	check(p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&database))
	if !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	tenant, err := p.CreateTenant(ctx, "Auto HTTP owner")
	check(err)
	foreign, err := p.CreateTenant(ctx, "Auto foreign owner")
	check(err)
	tokens := map[string]string{}
	for _, item := range []struct{ name, tenant, role string }{{"operator", tenant.ID, "operator"}, {"viewer", tenant.ID, "viewer"}, {"foreign", foreign.ID, "operator"}} {
		token, e := security.NewToken(32)
		check(e)
		tokens[item.name] = "vpt1_" + token
		_, e = p.CreateTenantAPIToken(ctx, item.tenant, item.name, item.role, security.HashToken(tokens[item.name]), time.Now().Add(time.Hour))
		check(e)
	}
	app := &application{store: p, adminToken: "synthetic-auto-admin"}
	mux := http.NewServeMux()
	app.registerAutoProfileRoutes(mux)
	mux.HandleFunc("GET /sub/{token}", app.getPublicVPNSubscription)
	mux.HandleFunc("GET /sub/{token}/{format}", app.getPublicVPNSubscription)
	mux.HandleFunc("GET /sub/{token}/info", app.getPublicSubscriptionInfo)
	request := func(method, path, auth string, body any, hwid string, want int) *httptest.ResponseRecorder {
		t.Helper()
		raw, e := json.Marshal(body)
		check(e)
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("User-Agent", "curl/fixture")
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		if hwid != "" {
			r.Header.Set("X-Hwid", hwid)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("HTTP status %d want %d", w.Code, want)
		}
		return w
	}
	ownerPath := "/api/v1/tenant/auto-profile"
	adminPath := "/api/v1/tenants/" + tenant.ID + "/auto-profile"
	settings := map[string]any{"enabled": true, "name": "🌐 Мой маршрут", "russia_direct": true}
	request("PUT", ownerPath, "", settings, "", 401)
	request("PUT", ownerPath, tokens["viewer"], settings, "", 403)
	request("PUT", adminPath, tokens["operator"], settings, "", 401)
	request("PUT", ownerPath, tokens["operator"], map[string]any{"name": "missing fields"}, "", 400)
	request("PUT", ownerPath, tokens["operator"], map[string]any{"enabled": true, "name": "bad\nname", "russia_direct": true}, "", 400)
	request("PUT", ownerPath, tokens["operator"], settings, "", 200)
	w := request("GET", ownerPath, tokens["viewer"], nil, "", 200)
	var read model.AutoProfileSettings
	check(json.Unmarshal(w.Body.Bytes(), &read))
	if !read.Enabled || read.Name != settings["name"] {
		t.Fatal("settings not persisted")
	}
	w = request("GET", ownerPath, tokens["foreign"], nil, "", 200)
	check(json.Unmarshal(w.Body.Bytes(), &read))
	if read.Enabled || read.Name != "Авто" {
		t.Fatal("foreign settings disclosed")
	}
	request("PUT", adminPath, app.adminToken, settings, "", 200)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "Auto HTTP subscriber", nil)
	check(err)
	release, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "99.0.18", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/fixture.zip", SHA256: strings.Repeat("e", 64), Channel: "testing"})
	check(err)
	check(p.ApproveCoreRelease(ctx, release.ID))
	for _, name := range []string{"one", "two"} {
		bootstrap := security.HashToken("auto-http-bootstrap-" + name)
		node, e := p.CreateNodeForRuntime(ctx, tenant.ID, name, bootstrap, "xray")
		check(e)
		_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("auto-http-agent-"+name), "0.2.34", "ubuntu", "24.04", "amd64", "xray")
		check(e)
		check(p.SaveDesiredState(ctx, node.ID, model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: release.Type, Version: release.Version, DownloadURL: release.DownloadURL, SHA256: release.SHA256, Channel: release.Channel}}, release.ID))
		address, port := name+".example.test", 443
		service, e := p.CreateVPNService(ctx, node.ID, name, "vless", "0.0.0.0", port, "tcp", "reality", &address, &port)
		check(e)
		_, e = p.ConfigureVPNServiceReality(ctx, service.ID, "example.test:443", "example.test", "firefox", "0123456789abcdef")
		check(e)
		_, e = p.Pool.Exec(ctx, `UPDATE vpn_service_reality SET public_key='BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc' WHERE service_id=$1`, service.ID)
		check(e)
		_, e = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
		check(e)
		_, e = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
		check(e)
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET applied_generation=desired_generation,last_seen_at=now() WHERE tenant_id=$1`, tenant.ID)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE deployments d SET status='healthy' FROM nodes n WHERE d.node_id=n.id AND n.tenant_id=$1 AND d.generation=n.applied_generation AND d.status IN('pending','applying')`, tenant.ID)
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO node_health(node_id,healthy,applied_generation) SELECT id,true,applied_generation FROM nodes WHERE tenant_id=$1`, tenant.ID)
	check(err)
	key := bytes.Repeat([]byte{73}, 32)
	t.Setenv("SUBSCRIPTION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(key))
	tokenID, err := newSubscriptionTokenID()
	check(err)
	token, hash, err := buildSubscriptionToken(key, tokenID, 1)
	check(err)
	_, err = p.CreateVPNClientSubscription(ctx, client.ID, tokenID, 1, hash, "auto-http")
	check(err)
	path := "/sub/" + token
	w = request("GET", path+"/info", "", nil, "", 200)
	var info store.PublicSubscriptionInfo
	check(json.Unmarshal(w.Body.Bytes(), &info))
	if info.AutoProfile == nil || info.AutoProfile.Name != settings["name"] {
		t.Fatal("public Auto display missing")
	}
	for _, secret := range []string{tenant.ID, client.ID, client.VLESSUUID, token} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("private metadata leaked")
		}
	}
	for _, format := range []string{"json", "singbox", "mihomo"} {
		w = request("GET", path+"/"+format, "", nil, "", 200)
		if w.Header().Get("X-PAUK-Auto-Assignment") != "subscription-refresh" || w.Header().Get("X-PAUK-Russia-Direct") == "client-rules-required" {
			t.Fatal("full configuration metadata")
		}
		if format == "json" {
			var configs []map[string]any
			check(json.Unmarshal(w.Body.Bytes(), &configs))
			if len(configs) != 3 || configs[0]["remarks"] != settings["name"] {
				t.Fatal("Auto/manual Xray profiles")
			}
			manual, _ := json.Marshal(configs[1:])
			if bytes.Contains(manual, []byte("pauk-ru-direct")) {
				t.Fatal("manual Xray routes changed")
			}
		} else {
			var config map[string]any
			check(json.Unmarshal(w.Body.Bytes(), &config))
			if format == "mihomo" {
				if len(config["proxies"].([]any)) != 3 || config["proxies"].([]any)[0].(map[string]any)["name"] != settings["name"] {
					t.Fatal("Auto/manual Mihomo profiles")
				}
			} else {
				count := 0
				found := false
				for _, raw := range config["outbounds"].([]any) {
					out := raw.(map[string]any)
					if out["type"] == "vless" {
						count++
						found = found || out["tag"] == settings["name"]
					}
				}
				if count != 3 || !found {
					t.Fatal("Auto/manual sing-box profiles")
				}
			}
		}
	}
	_, err = p.SetRegisteredDeviceLimit(ctx, client.ID, 1)
	check(err)
	request("GET", path+"/json", "", nil, "", 404)
	request("GET", path+"/json", "", nil, "AutoFixtureDeviceOne", 200)
	request("GET", path+"/json", "", nil, "AutoFixtureDeviceTwo", 404)
	_, err = p.SetRegisteredDeviceLimit(ctx, client.ID, 0)
	check(err)
	// Unhealthy pool removes only Auto, preserving every manual profile.
	_, err = p.Pool.Exec(ctx, `UPDATE node_health SET healthy=false WHERE node_id IN(SELECT id FROM nodes WHERE tenant_id=$1)`, tenant.ID)
	check(err)
	w = request("GET", path+"/json", "", nil, "", 200)
	var manual []map[string]any
	check(json.Unmarshal(w.Body.Bytes(), &manual))
	if len(manual) != 2 || w.Header().Get("X-PAUK-Auto-Name") != "" {
		t.Fatal("unhealthy pool did not preserve manual profiles")
	}
	settings["enabled"] = false
	request("PUT", ownerPath, tokens["operator"], settings, "", 200)
	w = request("GET", path+"/json", "", nil, "", 200)
	check(json.Unmarshal(w.Body.Bytes(), &manual))
	if len(manual) != 2 {
		t.Fatal("format changed when Auto disabled")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()-interval '1 hour' WHERE id=$1`, client.ID)
	check(err)
	request("GET", path+"/json", "", nil, "", 404)
}
