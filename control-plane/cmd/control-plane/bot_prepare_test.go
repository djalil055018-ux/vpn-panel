package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func TestBotPreparationHTTPDenials(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	app := &application{adminToken: "synthetic-bot-preparation-owner"}
	mux := http.NewServeMux()
	app.registerRemnawaveRoutes(mux)
	for _, kind := range []string{"no-auth", "tenant-token", "admin-role", "monitor-role", "wrong-mode", "missing-review", "bad-body", "duplicate", "unknown", "case", "oversize", "null"} {
		t.Run(kind, func(t *testing.T) {
			body := `{"tenant_id":"` + id + `"}`
			switch kind {
			case "bad-body":
				body = "{"
			case "null":
				body = "null"
			case "duplicate":
				body = `{"tenant_id":"` + id + `","tenant_id":"` + id + `"}`
			case "unknown":
				body = `{"tenant_id":"` + id + `","activate":true}`
			case "case":
				body = strings.Replace(body, "tenant_id", "Tenant_ID", 1)
			case "oversize":
				body = strings.Repeat(" ", 2049) + body
			}
			req := httptest.NewRequest("POST", "/api/v1/remnawave/imports/"+id+"/prepare-bot", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+app.adminToken)
			req.Header.Set("X-Remnawave-Mode", "prepare-held-bot")
			req.Header.Set("X-Reviewed-Inventory-SHA256", strings.Repeat("a", 64))
			want := 400
			switch kind {
			case "no-auth":
				req.Header.Del("Authorization")
				want = 401
			case "tenant-token":
				req.Header.Set("Authorization", "Bearer vpt1_synthetic")
				want = 401
			case "admin-role", "monitor-role":
				req = req.WithContext(store.WithAdminPrincipal(req.Context(), model.AdminSession{Account: model.AdminAccount{Role: strings.TrimSuffix(kind, "-role")}}))
				want = 403
			case "wrong-mode":
				req.Header.Set("X-Remnawave-Mode", "activate")
			case "missing-review":
				req.Header.Del("X-Reviewed-Inventory-SHA256")
			}
			res := httptest.NewRecorder()
			mux.ServeHTTP(res, req)
			if res.Code != want {
				t.Fatalf("HTTP%d want%d", res.Code, want)
			}
		})
	}
}
