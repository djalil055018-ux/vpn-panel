package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

func TestTenantViewerMetadataContainsNoCredentials(t *testing.T) {
	data, _ := json.Marshal(tenantClientMetadata(model.VPNClient{ID: "client", Name: "visible", VLESSUUID: "never-expose"}))
	if strings.Contains(string(data), "never-expose") || strings.Contains(string(data), "uuid") {
		t.Fatal("viewer response contained connection credentials")
	}
}
func TestTenantAPIRejectsAdminAndAgentBeforeDatabase(t *testing.T) {
	app := &application{adminToken: "admin-for-unit-test"}
	for _, token := range []string{"", "admin-for-unit-test", "agent-for-unit-test", "vpt1_short"} {
		r := httptest.NewRequest("GET", "/api/v1/tenant/me", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.requireTenantAPI("", false, func(_ http.ResponseWriter, _ *http.Request) { t.Fatal("handler reached") })(w, r)
		if w.Code != 401 {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	}
}

func TestTenantConnectionsRouteRequiresTenantCredential(t *testing.T) {
	app := &application{adminToken: "admin-for-unit-test"}
	mux := http.NewServeMux()
	app.registerTenantAPIRoutes(mux)
	for _, token := range []string{"", "admin-for-unit-test", "vpt1_short"} {
		r := httptest.NewRequest("GET", "/api/v1/tenant/clients/11111111-1111-4111-8111-111111111111/connections", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("profile route must reject credentials without caching: %d", w.Code)
		}
	}
}
