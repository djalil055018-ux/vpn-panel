//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestHysteriaServiceAPIIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("clone unavailable")
	}
	defer db.Close()
	var database string
	if db.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Match the store package's session lock for the one global reviewed pin.
	// Deferred release/tenant cleanup runs before the lock is relinquished.
	fixtureLock, err := db.Pool.Acquire(ctx)
	check(err)
	defer fixtureLock.Release()
	_, err = fixtureLock.Exec(ctx, `SELECT pg_advisory_lock(1448103505,7286122)`)
	check(err)
	defer func() {
		_, err := fixtureLock.Exec(context.Background(), `SELECT pg_advisory_unlock(1448103505,7286122)`)
		if err != nil {
			t.Error("release fixture lock cleanup failed")
		}
	}()
	var exists bool
	check(db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_releases WHERE core_type='hysteria2' AND version=$1 AND os='linux' AND architecture='amd64')`, model.HysteriaPinnedVersion).Scan(&exists))
	if exists {
		t.Fatal("isolated release fixture already exists")
	}
	var imported struct {
		Release model.CoreReleaseRecord `json:"release"`
		Created bool                    `json:"created"`
	}
	defer func() {
		if imported.Release.ID != "" {
			_, e := db.Pool.Exec(context.Background(), `DELETE FROM core_releases WHERE id=$1::uuid`, imported.Release.ID)
			if e != nil {
				t.Error("release fixture cleanup failed", e)
			}
		}
	}()
	tenant, err := db.CreateTenant(ctx, "CODEX-HYSTERIA-HTTP")
	check(err)
	defer func() {
		if _, e := db.Pool.Exec(context.Background(), `DELETE FROM vpn_services WHERE tenant_id=$1::uuid`, tenant.ID); e != nil {
			t.Error("fixture service cleanup failed", e)
		}
		if _, e := db.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID); e != nil {
			t.Error("fixture tenant cleanup failed", e)
		}
	}()
	bootstrap := security.HashToken("fixture-hys-http-bootstrap")
	node, err := db.CreateNodeForRuntime(ctx, tenant.ID, "CODEX-HYSTERIA-HTTP", bootstrap, "hysteria2")
	check(err)
	_, err = db.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("fixture-hys-http-agent"), "0.2.43", "ubuntu", "24.04", "amd64", "hysteria2")
	check(err)
	app := &application{store: db, adminToken: "fixture-hys-http-admin"}
	mux := http.NewServeMux()
	app.registerAccessPlanRoutes(mux)
	app.registerTLSServiceRoutes(mux)
	app.registerHysteriaOnboardingRoutes(mux)
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"POST /api/v1/nodes/{id}/desired-state", app.setDesiredState},
		{"POST /api/v1/nodes/{id}/vpn-services", app.createVPNService},
		{"POST /api/v1/vpn-services/{id}/enable", app.enableVPNService},
		{"POST /api/v1/vpn-services/{id}/disable", app.disableVPNService},
		{"GET /api/v1/vpn-clients/{id}/connections", app.listVPNClientConnections},
	} {
		mux.HandleFunc(route.pattern, app.requireAdmin(route.handler))
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	request := func(method, path string, input any, status int, output any) {
		t.Helper()
		raw, e := json.Marshal(input)
		check(e)
		req, e := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(raw))
		check(e)
		req.Header.Set("Authorization", "Bearer "+app.adminToken)
		req.Header.Set("Content-Type", "application/json")
		response, e := server.Client().Do(req)
		check(e)
		defer response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("%s request status %d, expected %d", method, response.StatusCode, status)
		}
		if output != nil {
			check(json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output))
		}
	}
	initializePath := "/api/v1/nodes/" + node.ID + "/initialize-hysteria"
	unauthorized := httptest.NewRecorder()
	mux.ServeHTTP(unauthorized, httptest.NewRequest("POST", initializePath, nil))
	if unauthorized.Code != 401 {
		t.Fatal("anonymous runtime initialization accepted")
	}
	request("POST", initializePath, nil, 409, nil)
	request("POST", "/api/v1/core-releases/hysteria2/import-reviewed", nil, 201, &imported)
	if !imported.Created || imported.Release.Approved || imported.Release.SHA256 != model.HysteriaPinnedSHA256 {
		t.Fatal("reviewed import changed approval or pin")
	}
	request("POST", "/api/v1/core-releases/hysteria2/import-reviewed", nil, 200, nil)
	request("POST", initializePath, nil, 409, nil)
	_, err = db.Pool.Exec(ctx, `UPDATE core_releases SET sha256=$2 WHERE id=$1::uuid`, imported.Release.ID, strings.Repeat("0", 64))
	check(err)
	request("POST", "/api/v1/core-releases/hysteria2/approve-reviewed", nil, 409, nil)
	request("POST", "/api/v1/core-releases/hysteria2/import-reviewed", nil, 409, nil)
	_, err = db.Pool.Exec(ctx, `UPDATE core_releases SET sha256=$2,revoked=true WHERE id=$1::uuid`, imported.Release.ID, model.HysteriaPinnedSHA256)
	check(err)
	request("POST", "/api/v1/core-releases/hysteria2/approve-reviewed", nil, 409, nil)
	_, err = db.Pool.Exec(ctx, `UPDATE core_releases SET revoked=false WHERE id=$1::uuid`, imported.Release.ID)
	check(err)
	request("POST", "/api/v1/core-releases/hysteria2/approve-reviewed", nil, 200, nil)
	request("POST", "/api/v1/core-releases/hysteria2/approve-reviewed", nil, 200, nil)
	request("POST", initializePath, nil, 202, nil)
	request("POST", initializePath, nil, 200, nil)
	var service model.VPNService
	request("POST", "/api/v1/nodes/"+node.ID+"/vpn-services", map[string]any{"name": "HTTP fixture", "protocol": "hysteria2", "listen": "0.0.0.0", "port": 18443, "transport": "udp", "security": "tls", "public_address": "hys-http.example.test", "public_port": 18443}, 201, &service)
	request("POST", "/api/v1/vpn-services/"+service.ID+"/enable", nil, 409, nil)
	cert, err := db.CreateNodeCertificate(ctx, node.ID, "hys-http.example.test", "letsencrypt", "http-01", "production", nil, true)
	check(err)
	_, err = db.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_before=now()-interval '1 day',not_after=now()+interval '60 days' WHERE id=$1::uuid`, cert.ID)
	check(err)
	request("PUT", "/api/v1/vpn-services/"+service.ID+"/tls", map[string]string{"certificate_id": cert.ID}, 200, nil)
	request("POST", "/api/v1/vpn-services/"+service.ID+"/enable", nil, 202, nil)
	var plan model.VPNAccessPlan
	request("POST", "/api/v1/tenants/"+tenant.ID+"/access-plans", map[string]string{"name": "HTTP Hysteria plan", "code": "http-hys"}, 201, &plan)
	request("POST", "/api/v1/access-plans/"+plan.ID+"/services/"+service.ID, nil, 200, nil)
	client, err := db.CreateVPNClient(ctx, tenant.ID, "HTTP Hysteria client", nil)
	check(err)
	assertAccess := func(count int) {
		t.Helper()
		var out struct {
			Connections []model.VPNClientConnection `json:"connections"`
		}
		request("GET", "/api/v1/vpn-clients/"+client.ID+"/connections", nil, 200, &out)
		if len(out.Connections) != count {
			t.Fatal("HTTP subscription access differs")
		}
		if count == 1 {
			u, e := url.Parse(out.Connections[0].URI)
			check(e)
			if u.Scheme != "hysteria2" || u.Query().Get("insecure") != "0" || u.Query().Get("sni") != cert.Domain {
				t.Fatal("HTTP Hysteria subscription is invalid")
			}
		}
		var raw []byte
		var state model.DesiredState
		check(db.Pool.QueryRow(ctx, `SELECT d.document FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, node.ID).Scan(&raw))
		check(json.Unmarshal(raw, &state))
		if len(state.Services) != 1 || len(state.Services[0].Clients) != count {
			t.Fatal("HTTP mutation did not rebuild effective desired access")
		}
	}
	assertAccess(0)
	request("POST", "/api/v1/access-plans/"+plan.ID+"/clients/"+client.ID, nil, 200, nil)
	assertAccess(1)
	request("POST", initializePath, nil, 200, nil)
	assertAccess(1)
	request("DELETE", "/api/v1/access-plans/"+plan.ID+"/clients/"+client.ID, nil, 200, nil)
	assertAccess(0)
}
