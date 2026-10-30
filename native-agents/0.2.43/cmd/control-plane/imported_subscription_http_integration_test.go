//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
	"vpn-platform/internal/subscriptioncompat"
)

func TestSubscriptionPublicDatabaseHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	var database string
	check(p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&database))
	if !strings.HasPrefix(database, "vpn_codex_test_delete_bot_") {
		t.Fatal("dedicated disposable bot DB required")
	}
	tenant, err := p.CreateTenant(ctx, "Public HTTP subscription")
	check(err)
	foreign, err := p.CreateTenant(ctx, "Foreign public HTTP subscription")
	check(err)
	raw, err := os.ReadFile("../../internal/remnawave/testdata/inventory.json")
	check(err)
	var source map[string]any
	check(json.Unmarshal(raw, &source))
	source["source_origin"] = "https://synthetic-public-http.example.test"
	for i, v := range source["users"].([]any) {
		u := v.(map[string]any)
		u["trafficLimitStrategy"] = "NO_RESET"
		u["shortUuid"] = "public-http-subscription-" + string(rune('a'+i))
		u["subscriptionUrl"] = "https://subscriptions.example.test/" + u["shortUuid"].(string)
		u["vlessUuid"] = []string{"e0000000-0000-4000-8000-", "e0000000-0000-4000-8001-", "e0000000-0000-4000-8002-"}[i] + tenant.ID[len(tenant.ID)-12:]
	}
	raw, err = json.Marshal(source)
	check(err)
	_, report, err := remnawave.Parse(raw)
	check(err)
	imported, _, err := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(err)
	_, err = p.PrepareBotBridge(ctx, tenant.ID, imported.ID, report.SHA256)
	check(err)
	_, err = p.PrepareRemnawaveNoResetQuota(ctx, imported.ID, tenant.ID, report.SHA256)
	check(err)
	var alias, clientID string
	check(p.Pool.QueryRow(ctx, `SELECT a.alias,b.client_id::text FROM bot_accounts b JOIN bot_subscription_aliases a USING(tenant_id,legacy_id) WHERE b.tenant_id=$1::uuid AND b.legacy_id=1 AND a.state='active'`, tenant.ID).Scan(&alias, &clientID))
	tokens := map[string]string{}
	for _, v := range []struct{ name, tenant, role string }{{"viewer", tenant.ID, "viewer"}, {"operator", tenant.ID, "operator"}, {"foreign", foreign.ID, "viewer"}, {"reseller", tenant.ID, "reseller"}} {
		random, e := security.NewToken(32)
		check(e)
		tokens[v.name] = "vpt1_" + random
		_, e = p.CreateTenantAPIToken(ctx, v.tenant, v.name, v.role, security.HashToken(tokens[v.name]), time.Now().Add(time.Hour))
		check(e)
	}
	t.Setenv("SUBSCRIPTION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	app := &application{store: p, adminToken: "synthetic-owner"}
	mux := http.NewServeMux()
	app.registerImportedSubscriptionRoutes(mux)
	app.registerImportedPageRoutes(mux)
	app.registerDeviceRoutes(mux)
	mux.HandleFunc("GET /sub/{token}", app.getPublicVPNSubscription)
	mux.HandleFunc("GET /sub/{token}/info", app.getPublicSubscriptionInfo)
	mux.HandleFunc("GET /sub/{token}/{format}", app.getPublicVPNSubscription)
	server := httptest.NewServer(mux)
	defer server.Close()
	deviceHeaders := http.Header{}
	request := func(path, role, body string, want int) []byte {
		t.Helper()
		req, e := http.NewRequest("GET", server.URL+path, strings.NewReader(body))
		check(e)
		req.Header.Set("User-Agent", "curl/8")
		for key, values := range deviceHeaders {
			req.Header[key] = values
		}
		if role == "root" {
			req.Header.Set("Authorization", "Bearer "+app.adminToken)
		} else if role != "" {
			req.Header.Set("Authorization", "Bearer "+tokens[role])
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		res, e := server.Client().Do(req)
		check(e)
		defer res.Body.Close()
		out, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		check(e)
		if res.StatusCode != want || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("public HTTP %s: got %d want %d", role, res.StatusCode, want)
		}
		for _, secret := range tokens {
			if bytes.Contains(out, []byte(secret)) {
				t.Fatal("reader credential leaked")
			}
		}
		return out
	}
	public := "/api/v1/public/imported-subscriptions/" + alias
	configs := importedPagePrefix + "/api/subscription-page-configs/"
	info := importedPagePrefix + "/api/sub/" + alias + "/info"
	selectPage := importedPagePrefix + "/api/subscriptions/subpage-config/" + alias
	request(public, "", "", 404)
	request("/sub/"+alias, "", "", 404)
	request("/sub/"+alias+"/info", "", "", 404)
	request(configs, "viewer", "", 404)
	request(importedPagePrefix+"/api/system/metadata", "viewer", "", 404)
	for _, role := range []string{"", "root"} {
		request(configs, role, "", 401)
	}
	request(configs, "reseller", "", 403)
	// Fixture activation is synthetic SQL only; this is not a production handoff.
	snap := publicSubscriptionFixture()
	pageID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	snap.Policy.PageID = &pageID
	bundle := store.ImportedSubscriptionBundle{Version: 1, Hosts: subscriptioncompat.Projection{InventorySHA256: report.SHA256, Hosts: []subscriptioncompat.BoundHost{}, Squads: []subscriptioncompat.SquadBinding{}},
		Policy: subscriptioncompat.PolicyProjection{InventorySHA256: report.SHA256, Global: snap.Policy, External: map[string]subscriptioncompat.Policy{},
			Pages: map[string]json.RawMessage{pageID: json.RawMessage(`{"synthetic":true}`)}, PageDetails: map[string]subscriptioncompat.PageMetadata{pageID: {ID: pageID, Name: "Default", ViewPosition: 1}}}, Templates: snap.Templates}
	settings := []byte(`{"synthetic_http":true}`)
	settingsHash := sha256.Sum256(settings)
	settingsSHA := hex.EncodeToString(settingsHash[:])
	bundle.Policy.SettingsSHA256 = settingsSHA
	wire, err := json.Marshal(bundle)
	check(err)
	sum := sha256.Sum256(wire)
	_, err = p.Pool.Exec(ctx, `INSERT INTO remnawave_subscription_settings(import_id,settings_sha256,source) VALUES($1::uuid,$2,$3)`, imported.ID, settingsSHA, settings)
	check(err)
	var revision string
	check(p.Pool.QueryRow(ctx, `INSERT INTO imported_subscription_revisions(tenant_id,import_id,inventory_sha256,settings_sha256,bundle_sha256,bundle) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6) RETURNING id::text`, tenant.ID, imported.ID, report.SHA256, settingsSHA, hex.EncodeToString(sum[:]), wire).Scan(&revision))
	_, err = p.Pool.Exec(ctx, `INSERT INTO imported_subscription_profiles(tenant_id,import_id,revision_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, tenant.ID, imported.ID, revision)
	check(err)
	request(public, "", "", 404)
	request("/sub/"+alias, "", "", 404)
	request("/sub/"+alias+"/info", "", "", 404)
	_, err = p.Pool.Exec(ctx, `UPDATE imported_subscription_profiles SET state='active',activation_sha256=$2,activated_at=now() WHERE tenant_id=$1::uuid`, tenant.ID, strings.Repeat("e", 64))
	check(err)
	request(public, "", "", 404)
	request("/sub/"+alias, "", "", 404)
	request("/sub/"+alias+"/info", "", "", 404)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='active',remnawave_hold=false,expires_at=now()+interval '7 days' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant.ID)
	check(err)
	for _, suffix := range []string{"", "/json", "/singbox", "/mihomo", "/stash", "/clash"} {
		request(public+suffix, "", "", 200)
	}

	// Canonical bot links use the same bearer alias, account and format renderer.
	for _, suffix := range []string{"", "/json", "/singbox", "/mihomo", "/stash", "/clash"} {
		oldBody := request(public+suffix, "", "", 200)
		newBody := request("/sub/"+alias+suffix, "", "", 200)
		if !bytes.Equal(oldBody, newBody) {
			t.Fatal("canonical alias changed configuration output")
		}
	}
	aliasPage := func(status string) store.PublicSubscriptionInfo {
		t.Helper()
		body := request("/sub/"+alias+"/info", "", "", 200)
		var info store.PublicSubscriptionInfo
		check(json.Unmarshal(body, &info))
		if info.Status != status || info.Brand != "PAUK" {
			t.Fatal("alias metadata status mismatch")
		}
		for _, secret := range []string{alias, clientID, tenant.ID, "vless_uuid", "token_hash"} {
			if bytes.Contains(body, []byte(secret)) {
				t.Fatal("alias metadata disclosed private material")
			}
		}
		return info
	}
	aliasPage("active")
	foreignCtx := store.WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "viewer"})
	if _, e := p.PublicSubscriptionInfo(foreignCtx, store.SubscriptionDeviceProof{Alias: alias}); e != store.ErrNotFound {
		t.Fatal("cross-tenant alias metadata")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()-interval '1 day' WHERE id=$1::uuid`, clientID)
	check(err)
	aliasPage("expired")
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()+interval '7 days' WHERE id=$1::uuid`, clientID)
	check(err)
	request("/sub/"+strings.Repeat("Z", 75)+"/info", "", "", 404)

	pageBody := request(configs, "viewer", "", 200)
	metadata := request(importedPagePrefix+"/api/system/metadata", "viewer", "", 200)
	if !bytes.Contains(metadata, []byte("VPN Infrastructure Platform "+controlPlaneVersion)) {
		t.Fatal("frontend startup identity")
	}
	if !bytes.Contains(pageBody, []byte(`"viewPosition":1`)) || !bytes.Contains(pageBody, []byte(`"total":1`)) {
		t.Fatal("frontend config list")
	}
	request(configs+pageID, "viewer", "", 200)
	request(configs+foreign.ID, "viewer", "", 404)
	request(configs, "foreign", "", 404)
	request(info, "foreign", "", 404)
	body := request(info, "viewer", "", 200)
	if !bytes.Contains(body, []byte(`"isFound":true`)) || !bytes.Contains(body, []byte(`"trafficLimitStrategy":"NO_RESET"`)) {
		t.Fatal("frontend browser envelope")
	}
	request(importedPagePrefix+"/api/sub/"+alias+"/json", "viewer", "", 200)
	request(importedPagePrefix+"/api/sub/"+alias+"/json", "", "", 200)
	request(info, "", "", 401)
	request(importedPagePrefix+"/api/sub/not-a-valid-alias/json", "", "", 404)
	selected := request(selectPage, "viewer", `{"requestHeaders":{"user-agent":"Mozilla/5","accept":"text/html"}}`, 200)
	if !bytes.Contains(selected, []byte(`"webpageAllowed":true`)) {
		t.Fatal("frontend page policy")
	}
	selected = request(selectPage, "viewer", `{"requestHeaders":{"user-agent":"curl/8"}}`, 200)
	if !bytes.Contains(selected, []byte(`"webpageAllowed":false`)) {
		t.Fatal("nonbrowser page policy")
	}
	request(selectPage, "viewer", `{"requestHeaders":{},"unknown":true}`, 400)
	key := bytes.Repeat([]byte{7}, 32)
	t.Setenv("SUBSCRIPTION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(key))
	tokenID, err := newSubscriptionTokenID()
	check(err)
	signed, tokenHash, err := buildSubscriptionToken(key, tokenID, 1)
	check(err)
	_, err = p.CreateVPNClientSubscription(ctx, clientID, tokenID, 1, tokenHash, subscriptionTokenPrefix(signed))
	check(err)
	request("/sub/"+signed, "", "", 200)
	request("/sub/"+signed+"/json", "", "", 200)
	deviceHeaders.Set("X-Hwid", "synthetic-device-new")
	deviceHeaders.Set("X-Device-Os", strings.Repeat("Ж", 512))
	deviceHeaders.Set("X-Device-Model", "Original model")
	request(public, "", "", 200)
	var created, updated time.Time
	var platform, deviceModel string
	check(p.Pool.QueryRow(ctx, `SELECT platform,device_model,created_at,updated_at FROM bot_devices WHERE tenant_id=$1::uuid AND legacy_id=1 AND hwid='synthetic-device-new'`, tenant.ID).Scan(&platform, &deviceModel, &created, &updated))
	if platform != strings.Repeat("Ж", 512) || deviceModel != "Original model" {
		t.Fatal("native observed device metadata")
	}
	deviceHeaders.Del("X-Device-Os")
	deviceHeaders.Set("X-Device-Model", "Updated model")
	request(public, "", "", 200)
	var original time.Time
	check(p.Pool.QueryRow(ctx, `SELECT platform,device_model,created_at,updated_at FROM bot_devices WHERE tenant_id=$1::uuid AND legacy_id=1 AND hwid='synthetic-device-new'`, tenant.ID).Scan(&platform, &deviceModel, &original, &updated))
	if platform != strings.Repeat("Ж", 512) || deviceModel != "Updated model" || !original.Equal(created) || !updated.After(created) {
		t.Fatal("device refresh changed creation or omitted metadata")
	}
	deviceHeaders.Set("Accept", "text/html")
	deviceHeaders.Set("X-Hwid", "synthetic-browser-only")
	request(public, "", "", 200)
	var observations int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_devices WHERE tenant_id=$1::uuid AND hwid='synthetic-browser-only'`, tenant.ID).Scan(&observations))
	if observations != 0 {
		t.Fatal("browser request added device history")
	}
	deviceHeaders.Del("Accept")
	deviceHeaders.Set("X-Hwid", "synthetic-device-new")
	t.Run("registered-device-enforcement", func(t *testing.T) {
		devices, e := p.RegisteredDevices(ctx, clientID)
		check(e)
		if devices.Count < 1 {
			t.Fatal("existing history missing")
		}
		_, e = p.SetRegisteredDeviceLimit(ctx, clientID, devices.Count)
		check(e)

		before, e := p.RegisteredDevices(ctx, clientID)
		check(e)
		deviceHeaders.Set("X-Hwid", "metadata-must-not-bind")
		if info := aliasPage("active"); info.DeviceLimit != devices.Count || info.DeviceCount != devices.Count {
			t.Fatal("alias device metadata mismatch")
		}
		afterInfo, e := p.RegisteredDevices(ctx, clientID)
		check(e)
		if before.Count != afterInfo.Count {
			t.Fatal("alias metadata registered device")
		}
		deviceHeaders.Set("X-Hwid", "synthetic-excess-device")
		for _, path := range []string{public, public + "/json", public + "/singbox", public + "/mihomo", public + "/stash", public + "/clash", importedPagePrefix + "/api/sub/" + alias + "/json", "/sub/" + signed, "/sub/" + signed + "/json", "/sub/" + alias, "/sub/" + alias + "/json"} {
			request(path, "", "", 404)
		}
		deviceHeaders.Del("X-Hwid")
		request(public, "", "", 404)
		request("/sub/"+alias, "", "", 404)
		request("/sub/"+alias+"/info", "", "", 200)
		deviceHeaders.Set("X-Hwid", "invalid")
		request(public, "", "", 404)
		request("/sub/"+alias, "", "", 404)
		request("/sub/"+alias+"/info", "", "", 200)
		deviceHeaders["X-Hwid"] = []string{"synthetic-device-new", "synthetic-excess-device"}
		request(public, "", "", 404)
		request("/sub/"+alias, "", "", 404)
		request("/sub/"+alias+"/info", "", "", 200)
		deviceHeaders.Set("X-Hwid", "synthetic-device-new")
		request(public, "", "", 200)
		deviceHeaders.Del("X-Hwid")
		deviceHeaders.Set("Accept", "text/html")
		limitedBrowser := request(public, "", "", 200)
		if !bytes.Contains(limitedBrowser, []byte(`"links":[]`)) || !bytes.Contains(limitedBrowser, []byte(`"deviceRegistrationRequired":true`)) {
			t.Fatal("limited browser exposed profiles")
		}
		limitedInfo := request(info, "viewer", "", 200)
		if !bytes.Contains(limitedInfo, []byte(`"links":[]`)) {
			t.Fatal("subscription page info bypassed limit")
		}
		deviceHeaders.Del("Accept")
		request("/api/v1/tenant/clients/"+clientID+"/devices", "foreign", "", 404)
		request("/api/v1/tenant/clients/"+clientID+"/devices", "viewer", "", 200)
		for _, role := range []string{"viewer", "foreign"} {
			req, e := http.NewRequest("PUT", server.URL+"/api/v1/tenant/clients/"+clientID+"/device-limit", strings.NewReader(`{"limit":0}`))
			check(e)
			req.Header.Set("Authorization", "Bearer "+tokens[role])
			req.Header.Set("Content-Type", "application/json")
			res, e := server.Client().Do(req)
			check(e)
			res.Body.Close()
			if res.StatusCode != 403 {
				t.Fatal("read-only device mutation allowed")
			}
		}
		operator := store.WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
		hwid := "synthetic-device-new"
		_, e = p.BotDeleteDevices(operator, 1, &hwid, strings.Repeat("a", 64))
		check(e)
		deviceHeaders.Set("X-Hwid", "synthetic-excess-device")
		request(public, "", "", 200)
		after, e := p.RegisteredDevices(ctx, clientID)
		check(e)
		if after.Count != devices.Count {
			t.Fatal("bot deletion and public admission used different registries")
		}
		_, e = p.SetRegisteredDeviceLimit(ctx, clientID, 0)
		check(e)
		deviceHeaders.Set("X-Hwid", "synthetic-device-new")
	})
	_, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(err)
	request(public, "", "", 200)
	request(configs, "viewer", "", 200)
	_, err = p.Pool.Exec(ctx, `UPDATE imported_subscription_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(err)
	request(public, "", "", 404)
	request("/sub/"+alias, "", "", 404)
	request("/sub/"+alias+"/info", "", "", 404)
	request(configs, "viewer", "", 404)
	request("/sub/"+alias+"/info", "", "", 404)
	request("/sub/"+signed, "", "", 404)
	device := subscriptioncompat.DeviceObservation{HWID: "synthetic-after-pause"}
	if err = p.ObserveImportedSubscriptionDevice(ctx, clientID, alias, device); err != store.ErrNotFound {
		t.Fatal("paused public profile recorded a device")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE imported_subscription_profiles SET state='active' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='disabled' WHERE id=$1::uuid`, clientID)
	check(err)
	body = request(public+"/json", "", "", 200)
	if !bytes.Contains(body, []byte("disabledUsers")) {
		t.Fatal("disabled HTTP notice")
	}
	request("/sub/"+signed, "", "", 404)
	aliasPage("disabled")
	// The HTTP request above used a valid device header; disabled accounts keep
	// source history, while their response still contains dummy profiles only.
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='active' WHERE id=$1::uuid`, clientID)
	check(err)
	operator := store.WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	_, err = p.BotUserAction(operator, 1, "revoke", strings.Repeat("f", 64), 0)
	check(err)
	request(public, "", "", 404)
	request("/sub/"+alias, "", "", 404)
	request("/sub/"+alias+"/info", "", "", 404)
	request(info, "viewer", "", 404)
	request("/sub/"+signed, "", "", 404)
	if err = p.ObserveImportedSubscriptionDevice(ctx, clientID, alias, device); err != store.ErrNotFound {
		t.Fatal("revoked alias resurrected device history")
	}
}
