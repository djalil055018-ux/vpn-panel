package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func TestBotSquadPreparationDenials(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	valid := `{"tenant_id":"` + id + `","revision_id":"` + id + `","bundle_sha256":"` + strings.Repeat("b", 64) + `"}`
	if _, err := decodeBotSquadPreparation([]byte(valid)); err != nil {
		t.Fatal("reviewed identity rejected")
	}
	for _, bad := range []string{"null", "[]", valid + "{}", strings.Replace(valid, "tenant_id", "Tenant_ID", 1), strings.Replace(valid, `"tenant_id":`, `"tenant_id":"`+id+`","tenant_id":`, 1), strings.Replace(valid, `"bundle_sha256":`, `"activate":true,"bundle_sha256":`, 1), strings.Replace(valid, strings.Repeat("b", 64), strings.Repeat("B", 64), 1)} {
		if _, err := decodeBotSquadPreparation([]byte(bad)); err == nil {
			t.Fatal("ambiguous or unreviewed request accepted")
		}
	}
	app := &application{adminToken: "synthetic-squad-owner"}
	mux := http.NewServeMux()
	app.registerRemnawaveRoutes(mux)
	for _, kind := range []string{"no-auth", "tenant-token", "admin-role", "monitor-role", "wrong-mode", "missing-review", "bad-body", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			body := valid
			if kind == "bad-body" {
				body = `{"activate":true}`
			}
			if kind == "oversize" {
				body = strings.Repeat(" ", 2049) + body
			}
			req := httptest.NewRequest("POST", "/api/v1/remnawave/imports/"+id+"/prepare-bot-squads", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+app.adminToken)
			req.Header.Set("X-Remnawave-Mode", "prepare-held-bot-squads")
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
				t.Fatalf("HTTP%d, want%d", res.Code, want)
			}
		})
	}
}
