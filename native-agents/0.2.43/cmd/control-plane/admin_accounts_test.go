package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdministratorCredentialBoundary(t *testing.T) {
	app := &application{adminToken: "root-fixture"}
	for _, token := range []string{"", "agent-fixture", "vpt1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "vpa1_short"} {
		r := httptest.NewRequest("GET", "/api/v1/admin/accounts", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.requireAdmin(func(http.ResponseWriter, *http.Request) { t.Fatal("invalid credential reached handler") })(w, r)
		if w.Code != 401 {
			t.Fatalf("invalid credential status %d", w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/v1/admin/bootstrap", nil)
	r.Header.Set("Authorization", "Bearer vpa1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	w := httptest.NewRecorder()
	app.requireRoot(func(http.ResponseWriter, *http.Request) { t.Fatal("personal session reached root handler") })(w, r)
	if w.Code != 401 {
		t.Fatal("root boundary failed")
	}
}

func TestMonitorDenyByDefault(t *testing.T) {
	for _, pattern := range []string{"GET /api/v1/tenants", "GET /api/v1/vpn-clients/{id}", "GET /api/v1/nodes/{id}/desired-state", "POST /api/v1/nodes/{id}/rebuild-desired-state", "PATCH /api/v1/admin/accounts/{id}", "GET /api/v1/new-sensitive-endpoint", ""} {
		if monitorRouteAllowed(pattern) {
			t.Fatalf("monitor admitted %s", pattern)
		}
	}
	for _, pattern := range []string{"GET /api/v1/admin/me/mfa", "POST /api/v1/admin/me/mfa/enroll", "POST /api/v1/admin/me/mfa/confirm", "POST /api/v1/admin/me/mfa/disable", "POST /api/v1/admin/me/mfa/recovery-codes", "GET /api/v1/operations/status", "GET /api/v1/operations/incidents", "GET /api/v1/admin/me", "PUT /api/v1/admin/me/password"} {
		if !monitorRouteAllowed(pattern) {
			t.Fatalf("monitor rejected %s", pattern)
		}
	}
}

func TestAdministratorLoginThrottle(t *testing.T) {
	username := "rate-test-fixture"
	for i := 0; i < 10; i++ {
		if !admitAdminLogin(username) {
			t.Fatal("throttled too early")
		}
	}
	if admitAdminLogin("RATE-TEST-FIXTURE") {
		t.Fatal("case change bypassed throttle")
	}
}
