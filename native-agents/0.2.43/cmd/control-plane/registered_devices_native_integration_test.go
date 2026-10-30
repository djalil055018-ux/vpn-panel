//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
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

// Use real profile generators and database grants: neither protocol's download
// branch may disclose configuration before the device admission check.
func TestRegisteredDeviceNativeHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
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
	signing := bytes.Repeat([]byte{91}, 32)
	t.Setenv("SUBSCRIPTION_SIGNING_KEY", base64.RawURLEncoding.EncodeToString(signing))
	for _, protocol := range []string{"wireguard", "openvpn"} {
		t.Run(protocol, func(t *testing.T) {
			check := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			tenant, e := p.CreateTenant(ctx, "Native device HTTP "+protocol)
			check(e)
			core := model.CoreReleaseRecord{Type: "xray", Version: "26.7.30", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/xray.zip", SHA256: strings.Repeat("a", 64), Channel: "testing"}
			securityMode := "wireguard"
			if protocol == "openvpn" {
				core.Type = "openvpn"
				core.Version = model.OpenVPNPinnedVersion
				core.DownloadURL = model.OpenVPNPinnedDownloadURL
				core.SHA256 = model.OpenVPNPinnedSHA256
				securityMode = "tls"
			}
			release, e := p.CreateCoreRelease(ctx, core)
			check(e)
			check(p.ApproveCoreRelease(ctx, release.ID))
			bootstrap := security.HashToken("native-device-" + protocol)
			node, e := p.CreateNodeForRuntime(ctx, tenant.ID, "Native devices "+protocol, bootstrap, core.Type)
			check(e)
			_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("native-device-agent-"+protocol), "0.2.33", "ubuntu", "24.04", "amd64", core.Type)
			check(e)
			initial := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: release.Type, Version: release.Version, DownloadURL: release.DownloadURL, SHA256: release.SHA256, Channel: release.Channel}}
			check(p.SaveDesiredState(ctx, node.ID, initial, release.ID))
			address, port := "device-profile.example.test", 11941
			service, e := p.CreateVPNService(ctx, node.ID, "Native file", protocol, "127.0.0.1", port, "udp", securityMode, &address, &port)
			check(e)
			_, e = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
			check(e)
			client, e := p.CreateVPNClient(ctx, tenant.ID, "Native registered devices", nil)
			check(e)
			_, e = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
			check(e)
			connections, e := p.ListVPNClientConnections(ctx, client.ID)
			check(e)
			if len(connections) != 1 || connections[0].Config == "" {
				t.Fatal("real native profile fixture missing")
			}
			tokenID, e := newSubscriptionTokenID()
			check(e)
			token, tokenHash, e := buildSubscriptionToken(signing, tokenID, 1)
			check(e)
			_, e = p.CreateVPNClientSubscription(ctx, client.ID, tokenID, 1, tokenHash, "native-devices")
			check(e)
			_, e = p.SetRegisteredDeviceLimit(ctx, client.ID, 1)
			check(e)
			app := &application{store: p}
			mux := http.NewServeMux()
			mux.HandleFunc("GET /sub/{token}", app.getPublicVPNSubscription)
			path := subscriptionPath(token) + "?format=" + protocol + "&service_id=" + service.ID
			request := func(hwid string, want int, profile bool) *httptest.ResponseRecorder {
				t.Helper()
				r := httptest.NewRequest("GET", path, nil)
				if hwid != "" {
					r.Header.Set("X-Hwid", hwid)
				}
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				if w.Code != want {
					t.Fatalf("HTTP %d want %d", w.Code, want)
				}
				if (w.Body.String() == connections[0].Config) != profile {
					t.Fatal("native profile disclosure mismatch")
				}
				return w
			}
			w := request("", 404, false)
			if w.Header().Get("X-Hwid-Not-Supported") != "true" {
				t.Fatal("unidentified request admitted")
			}
			request("invalid", 404, false)
			request("NativeFixtureDeviceOne", 200, true)
			w = request("NativeFixtureDeviceTwo", 404, false)
			if w.Header().Get("X-Hwid-Max-Devices-Reached") != "true" {
				t.Fatal("limit header absent")
			}
			request("NativeFixtureDeviceOne", 200, true)
			registered, e := p.RegisteredDevices(ctx, client.ID)
			check(e)
			if registered.Count != 1 {
				t.Fatal("native file requests exceeded cap")
			}
			_, e = p.DeleteRegisteredDevice(ctx, client.ID, registered.Devices[0].ID)
			check(e)
			request("NativeFixtureDeviceTwo", 200, true)
			_, e = p.SetRegisteredDeviceLimit(ctx, client.ID, 0)
			check(e)
			request("", 200, true)
		})
	}
}
