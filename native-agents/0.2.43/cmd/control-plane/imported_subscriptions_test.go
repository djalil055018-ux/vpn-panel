package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func TestSubscriptionPreparationHTTPDenials(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	app := &application{adminToken: "synthetic-public-owner"}
	mux := http.NewServeMux()
	app.registerRemnawaveRoutes(mux)
	for _, kind := range []string{"no-auth", "tenant-token", "admin-role", "monitor-role", "wrong-mode", "missing-inventory", "missing-settings", "missing-tenant", "bad-kind", "duplicate-fields", "bad-json", "wrong-hash", "empty"} {
		t.Run(kind, func(t *testing.T) {
			body := `{"format":1,"kind":"remnawave_subscription_settings_snapshot"}`
			switch kind {
			case "bad-kind":
				body = `{"format":1,"kind":"activate"}`
			case "duplicate-fields":
				body = `{"format":1,"format":1,"kind":"remnawave_subscription_settings_snapshot"}`
			case "bad-json":
				body = "{"
			case "empty":
				body = ""
			}
			req := httptest.NewRequest("POST", "/api/v1/remnawave/imports/"+id+"/prepare-subscriptions", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+app.adminToken)
			req.Header.Set("X-Remnawave-Mode", "prepare-held-subscriptions")
			req.Header.Set("X-Remnawave-Tenant-ID", id)
			req.Header.Set("X-Reviewed-Inventory-SHA256", strings.Repeat("a", 64))
			sum := sha256.Sum256([]byte(body))
			req.Header.Set("X-Reviewed-Settings-SHA256", hex.EncodeToString(sum[:]))
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
			case "missing-inventory":
				req.Header.Del("X-Reviewed-Inventory-SHA256")
			case "missing-settings":
				req.Header.Del("X-Reviewed-Settings-SHA256")
			case "missing-tenant":
				req.Header.Del("X-Remnawave-Tenant-ID")
			case "wrong-hash":
				req.Header.Set("X-Reviewed-Settings-SHA256", strings.Repeat("0", 64))
			}
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, req)
			if recorder.Code != want {
				t.Fatalf("denial %s returned %d", kind, recorder.Code)
			}
			if strings.Contains(recorder.Body.String(), body) && len(body) > 10 {
				t.Fatal("source body leaked in error")
			}
		})
	}
}
