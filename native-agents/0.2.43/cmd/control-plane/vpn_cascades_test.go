package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCascadeHTTPAuthenticationAndResourceBoundary(t *testing.T) {
	app := &application{adminToken: "root-fixture"}
	mux := http.NewServeMux()
	app.registerCascadeRoutes(mux)
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/v1/tenants/not-an-id/cascades"}, {"POST", "/api/v1/tenants/not-an-id/cascades"},
		{"GET", "/api/v1/vpn-cascades/not-an-id"}, {"PUT", "/api/v1/vpn-cascades/not-an-id"}, {"DELETE", "/api/v1/vpn-cascades/not-an-id"},
	} {
		for _, token := range []string{"", "agent-fixture", "vpt1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "root-fixture"} {
			r := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			want := http.StatusUnauthorized
			if token == "root-fixture" {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Fatalf("cascade route %s: status %d want %d", route.method, w.Code, want)
			}
		}
	}
	for _, route := range []string{"GET /api/v1/tenants/{id}/cascades", "GET /api/v1/vpn-cascades/{id}", "POST /api/v1/tenants/{id}/cascades", "PUT /api/v1/vpn-cascades/{id}", "DELETE /api/v1/vpn-cascades/{id}"} {
		if monitorRouteAllowed(route) {
			t.Fatal("monitor admitted infrastructure management route")
		}
	}
}

func TestCascadeHTTPRejectsPrivateAndUnboundedInput(t *testing.T) {
	for _, body := range []string{`{"transit_uuid":"private"}`, `{"xray_cascades":{}}`, `{"raw_config":{}}`, `{} {}`, `[]`, `{"name":"` + strings.Repeat("a", 17000) + `"}`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		w := httptest.NewRecorder()
		if _, ok := readCascadeInput(w, r); ok || w.Code != http.StatusBadRequest {
			t.Fatal("invalid cascade body accepted")
		}
		if strings.Contains(w.Body.String(), "private") {
			t.Fatal("private input reflected in error")
		}
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"Example","plan_id":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA","entry_service_id":"BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB","exit_service_id":"CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC","entry_port":9443,"enabled":false}`))
	w := httptest.NewRecorder()
	input, ok := readCascadeInput(w, r)
	if !ok || input.PlanID != strings.ToLower(input.PlanID) || input.EntryServiceID != strings.ToLower(input.EntryServiceID) || input.ExitServiceID != strings.ToLower(input.ExitServiceID) || input.EntryPort != 9443 {
		t.Fatal("valid draft input rejected")
	}
}
