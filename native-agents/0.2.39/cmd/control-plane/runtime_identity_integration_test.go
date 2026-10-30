//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestRuntimeRegistrationHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("clone connection failed")
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
	tenant, err := db.CreateTenant(ctx, "CODEX-RUNTIME-REGISTER")
	check(err)
	defer db.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
	app := &application{store: db}
	mux := http.NewServeMux()
	app.registerAgentCapabilityRoutes(mux)
	mux.HandleFunc("POST /api/v1/agent/register", app.registerAgent)
	mux.HandleFunc("POST /api/v1/agent/health", app.requireAgent(app.agentHealth))
	server := httptest.NewServer(mux)
	defer server.Close()
	client := agent.NewClient(server.URL)
	capResponse := httptest.NewRecorder()
	mux.ServeHTTP(capResponse, httptest.NewRequest("GET", "/api/v1/agent/capabilities", nil))
	var capabilities map[string]any
	if capResponse.Code != 200 || capResponse.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(capResponse.Body.Bytes(), &capabilities) != nil || capabilities["bootstrap_inspection"] != true || capabilities["runtime_selection"] != true {
		t.Fatal("capability discovery contract failed")
	}
	system := agent.SystemInfo{OSName: "ubuntu", OSVersion: "24.04", Architecture: "amd64"}
	for _, runtime := range []string{"xray", "hysteria2"} {
		bootstrap := "runtime-http-fixture-" + runtime
		node, err := db.CreateNodeForRuntime(ctx, tenant.ID, "CODEX-HTTP-"+runtime, security.HashToken(bootstrap), runtime)
		check(err)
		inspect := func(token string) *httptest.ResponseRecorder {
			req := httptest.NewRequest("GET", "/api/v1/agent/bootstrap-info", nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, req)
			return response
		}
		if inspect("").Code != 401 || inspect("wrong-fixture-bootstrap").Code != 401 {
			t.Fatal("anonymous or wrong bootstrap inspection accepted")
		}
		for attempt := 0; attempt < 2; attempt++ {
			response := inspect(bootstrap)
			var info map[string]string
			if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &info) != nil || len(info) != 2 || info["node_id"] != node.ID || info["runtime_core"] != runtime {
				t.Fatal("safe bootstrap inspection failed")
			}
		}
		var consumed bool
		check(db.Pool.QueryRow(ctx, `SELECT bootstrap_used_at IS NOT NULL FROM nodes WHERE id=$1::uuid`, node.ID).Scan(&consumed))
		if consumed {
			t.Fatal("inspection consumed bootstrap")
		}
		wrong := "hysteria2"
		if runtime == "hysteria2" {
			wrong = "xray"
		}
		if _, err = client.RegisterForRuntime(ctx, bootstrap, "0.2.25", system, wrong); err == nil {
			t.Fatal("wrong runtime registration succeeded")
		}
		request := httptest.NewRequest("POST", "/api/v1/agent/register", strings.NewReader(`{"runtime_core":"hysteria2","agent_version":"0.2.23","os_name":"ubuntu","os_version":"24.04","architecture":"amd64"}`))
		request.Header.Set("Authorization", "Bearer "+bootstrap)
		response := httptest.NewRecorder()
		app.registerAgent(response, request)
		if response.Code != 400 {
			t.Fatal("old Hysteria agent was not rejected before token consumption")
		}
		registration, err := client.RegisterForRuntime(ctx, bootstrap, "0.2.25", system, runtime)
		check(err)
		if registration.NodeID != node.ID || registration.RuntimeCore != runtime || registration.AgentToken == "" {
			t.Fatal("registration identity not preserved")
		}
		authenticated, err := db.NodeByAgentToken(ctx, security.HashToken(registration.AgentToken))
		check(err)
		if authenticated.RuntimeCore != runtime {
			t.Fatal("permanent credential bound to wrong runtime")
		}
		if inspect(bootstrap).Code != 401 || inspect(registration.AgentToken).Code != 401 {
			t.Fatal("used bootstrap or permanent credential accepted for bootstrap inspection")
		}
		raw, _ := json.Marshal(model.HealthReport{Core: wrong, AgentVersion: "0.2.25", CheckedAt: time.Now()})
		request = httptest.NewRequest("POST", "/api/v1/agent/health", strings.NewReader(string(raw)))
		request.Header.Set("Authorization", "Bearer "+registration.AgentToken)
		response = httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != 409 {
			t.Fatal("health runtime mismatch was not reported as a conflict")
		}
		check(client.Health(ctx, registration.AgentToken, model.HealthReport{Core: runtime, AgentVersion: "0.2.25", CheckedAt: time.Now()}))
	}
}
