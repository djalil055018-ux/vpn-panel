package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func TestXrayProfilePreparationRequest(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	valid := `{"tenant_id":"` + id + `","node_id":"` + id + `","source_node_id":"` + id + `","tls_assignments":[]}`
	if _, a, e := decodeXrayPreparation([]byte(valid)); e != nil || len(a) != 0 {
		t.Fatal("valid empty TLS assignment rejected")
	}
	withTLS := strings.Replace(valid, "[]", `[{"source_inbound_id":"`+id+`","certificate_id":"`+id+`"}]`, 1)
	if _, a, e := decodeXrayPreparation([]byte(withTLS)); e != nil || len(a) != 1 {
		t.Fatal("valid explicit certificate rejected")
	}
	for _, bad := range []string{
		"null", "[]", valid + "{}", strings.Replace(valid, "[]", "null", 1),
		strings.Replace(valid, "tenant_id", "Tenant_ID", 1),
		strings.Replace(valid, `"tenant_id":`, `"tenant_id":"`+id+`","tenant_id":`, 1),
		strings.Replace(valid, `"tls_assignments":[]`, `"enabled":true,"tls_assignments":[]`, 1),
		strings.Replace(withTLS, `"certificate_id":`, `"certificate_id":"`+id+`","certificate_id":`, 1),
		strings.Replace(withTLS, "source_inbound_id", "Source_Inbound_ID", 1),
		strings.Replace(withTLS, `"certificate_id":`, `"private_key":"hidden","certificate_id":`, 1),
		strings.Replace(withTLS, `"certificate_id":`, `"key_file":"/private/key","certificate_id":`, 1),
		strings.Repeat(" ", 16385) + valid,
	} {
		if _, _, e := decodeXrayPreparation([]byte(bad)); e == nil {
			t.Fatal("ambiguous or unsupported preparation accepted")
		}
	}

	// Nil store proves every denial happens before any database action.
	app := &application{adminToken: "synthetic-xray-owner"}
	mux := http.NewServeMux()
	app.registerRemnawaveRoutes(mux)
	for _, kind := range []string{"no-auth", "tenant-token", "admin-role", "monitor-role", "wrong-mode", "missing-review", "bad-body"} {
		t.Run(kind, func(t *testing.T) {
			body := valid
			if kind == "bad-body" {
				body = `{"enabled":true}`
			}
			req := httptest.NewRequest("POST", "/api/v1/remnawave/imports/"+id+"/prepare-xray-node", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+app.adminToken)
			req.Header.Set("X-Remnawave-Mode", "prepare-held-xray")
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
				role := strings.TrimSuffix(kind, "-role")
				req = req.WithContext(store.WithAdminPrincipal(req.Context(), model.AdminSession{Account: model.AdminAccount{Role: role}}))
				want = 403
			case "wrong-mode":
				req.Header.Set("X-Remnawave-Mode", "activate")
			case "missing-review":
				req.Header.Del("X-Reviewed-Inventory-SHA256")
			}
			res := httptest.NewRecorder()
			mux.ServeHTTP(res, req)
			if res.Code != want {
				t.Fatal("preparation authorization or validation bypass")
			}
			var response map[string]any
			if json.Unmarshal(res.Body.Bytes(), &response) != nil || strings.Contains(res.Body.String(), "hidden") {
				t.Fatal("unsafe response")
			}
		})
	}
}
