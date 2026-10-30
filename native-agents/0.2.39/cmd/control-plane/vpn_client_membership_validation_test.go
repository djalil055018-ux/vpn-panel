package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A nil store proves malformed identifiers are rejected before any DB access.
func TestVPNClientMembershipRejectsMalformedIDs(t *testing.T) {
	app := &application{adminToken: "membership-validation-test"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/vpn-clients/{id}/services", app.requireAdmin(app.listVPNClientDirectServices))
	mux.HandleFunc("DELETE /api/v1/vpn-services/{id}/clients/{client_id}", app.requireAdmin(app.detachVPNClientFromService))
	const valid = "11111111-1111-4111-8111-111111111111"
	for _, invalid := range []string{"not-a-uuid", "1111", valid + "extra", "gggggggg-1111-4111-8111-111111111111"} {
		for _, tc := range []struct{ method, path string }{
			{"GET", "/api/v1/vpn-clients/" + invalid + "/services"},
			{"DELETE", "/api/v1/vpn-services/" + invalid + "/clients/" + valid},
			{"DELETE", "/api/v1/vpn-services/" + valid + "/clients/" + invalid},
		} {
			t.Run(tc.method+tc.path, func(t *testing.T) {
				r := httptest.NewRequest(tc.method, tc.path, nil)
				r.Header.Set("Authorization", "Bearer "+app.adminToken)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status=%d, want 400", w.Code)
				}
				if strings.Contains(w.Body.String(), invalid) || strings.Contains(w.Body.String(), "SQLSTATE") {
					t.Fatal("input or database details exposed")
				}
			})
		}
	}
}

func TestVPNClientMembershipCredentialBoundary(t *testing.T) {
	app := &application{adminToken: "membership-validation-test"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/vpn-clients/{id}/services", app.requireAdmin(app.listVPNClientDirectServices))
	mux.HandleFunc("DELETE /api/v1/vpn-services/{id}/clients/{client_id}", app.requireAdmin(app.detachVPNClientFromService))
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/vpn-clients/not-a-uuid/services"},
		{"DELETE", "/api/v1/vpn-services/not-a-uuid/clients/not-a-uuid"},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s status=%d, want 401", tc.method, w.Code)
		}
	}
	for _, pattern := range []string{"GET /api/v1/vpn-clients/{id}/services", "DELETE /api/v1/vpn-services/{id}/clients/{client_id}"} {
		if monitorRouteAllowed(pattern) {
			t.Fatalf("monitor admitted membership route: %s", pattern)
		}
	}
}
