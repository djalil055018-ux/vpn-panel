package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func TestNodeRenameHTTPDenials(t *testing.T) {
	a := &application{adminToken: "synthetic-node-owner"}
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /api/v1/nodes/{id}", a.requireAdmin(a.renameNode))
	id := "11111111-1111-4111-8111-111111111111"
	for _, c := range []struct {
		name, path, body, role string
		tenant                 bool
		status                 int
	}{
		{name: "no-auth", path: id, body: `{"name":"new"}`, status: http.StatusUnauthorized},
		{name: "admin-role", path: id, body: `{"name":"new"}`, role: "admin", status: http.StatusForbidden},
		{name: "monitor-role", path: id, body: `{"name":"new"}`, role: "monitor", status: http.StatusForbidden},
		{name: "tenant-principal", path: id, body: `{"name":"new"}`, tenant: true, status: http.StatusForbidden},
		{name: "invalid-id", path: "bad", body: `{"name":"new"}`, status: http.StatusBadRequest},
		{name: "missing-name", path: id, body: `{}`, status: http.StatusBadRequest},
		{name: "unknown-field", path: id, body: `{"name":"new","force":true}`, status: http.StatusBadRequest},
		{name: "duplicate-field", path: id, body: `{"name":"first","name":"second"}`, status: http.StatusBadRequest},
		{name: "multiple-values", path: id, body: `{"name":"new"}{}`, status: http.StatusBadRequest},
		{name: "null", path: id, body: `null`, status: http.StatusBadRequest},
		{name: "empty-name", path: id, body: `{"name":"   "}`, status: http.StatusBadRequest},
		{name: "control-character", path: id, body: `{"name":"bad\nname"}`, status: http.StatusBadRequest},
		{name: "too-long", path: id, body: `{"name":"` + strings.Repeat("n", 81) + `"}`, status: http.StatusBadRequest},
		{name: "oversize", path: id, body: strings.Repeat(" ", 16385), status: http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPatch, "/api/v1/nodes/"+c.path, strings.NewReader(c.body))
			r.Header.Set("Authorization", "Bearer "+a.adminToken)
			if c.name == "no-auth" {
				r.Header.Del("Authorization")
			}
			if c.role != "" {
				r = r.WithContext(store.WithAdminPrincipal(r.Context(), model.AdminSession{Account: model.AdminAccount{Role: c.role}}))
			}
			if c.tenant {
				r = r.WithContext(store.WithTenantPrincipal(r.Context(), model.TenantAPIToken{Role: "operator"}))
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != c.status {
				t.Fatalf("got %d want %d: %s", w.Code, c.status, w.Body.String())
			}
		})
	}
}
