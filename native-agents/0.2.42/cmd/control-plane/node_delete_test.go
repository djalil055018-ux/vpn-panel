package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func TestNodeDeleteHTTPDenials(t *testing.T) {
	a := &application{adminToken: "synthetic-node-owner"}
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /api/v1/nodes/{id}", a.requireAdmin(a.deleteNode))
	id := "11111111-1111-4111-8111-111111111111"
	for _, c := range []struct {
		name, body, role string
		status           int
	}{
		{"no-auth", `{}`, "", 401}, {"tenant", `{}`, "", 401}, {"admin", `{}`, "admin", 403}, {"monitor", `{}`, "monitor", 403},
		{"missing", `{}`, "", 400}, {"not-stopped", `{"confirm_name":"first","server_stopped":false}`, "", 400},
		{"online-decommission", `{"confirm_name":"first","server_stopped":false,"decommission_online":true}`, "admin", 403},
		{"duplicate", `{"confirm_name":"first","confirm_name":"other","server_stopped":true}`, "", 400},
		{"case", `{"Confirm_Name":"first","server_stopped":true}`, "", 400}, {"unknown", `{"confirm_name":"first","server_stopped":true,"force":true}`, "", 400},
		{"two", `{"confirm_name":"first","server_stopped":true}{}`, "", 400}, {"null", `null`, "", 400}, {"oversize", strings.Repeat(" ", 16385), "", 400},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("DELETE", "/api/v1/nodes/"+id, strings.NewReader(c.body))
			r.Header.Set("Authorization", "Bearer "+a.adminToken)
			if c.name == "no-auth" {
				r.Header.Del("Authorization")
			}
			if c.name == "tenant" {
				r.Header.Set("Authorization", "Bearer vpt1_synthetic")
			}
			if c.role != "" {
				r = r.WithContext(store.WithAdminPrincipal(r.Context(), model.AdminSession{Account: model.AdminAccount{Role: c.role}}))
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != c.status {
				t.Fatalf("got%d want%d", w.Code, c.status)
			}
		})
	}
}
