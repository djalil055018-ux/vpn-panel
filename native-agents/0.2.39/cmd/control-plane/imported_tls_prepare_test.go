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

func TestImportedTLSPreparationRequest(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	req := store.ImportedTLSRequest{TenantID: id, NodeID: id, SourceNodeID: id, Domain: "import.example.test", FullchainPEM: "synthetic-public-chain", AdoptionSHA256: strings.Repeat("a", 64)}
	wire, _ := json.Marshal(req)
	valid := string(wire)
	if _, e := decodeImportedTLSPreparation(wire); e != nil {
		t.Fatal("typed preparation request rejected")
	}
	long := req
	long.FullchainPEM = strings.Repeat("public-chain", 2000)
	large, _ := json.Marshal(long)
	if len(large) <= 16384 {
		t.Fatal("large request fixture is too small")
	}
	if _, e := decodeImportedTLSPreparation(large); e != nil {
		t.Fatal("bounded public chain request inherited the bot limit")
	}
	long.FullchainPEM = strings.Repeat("a", 65537)
	large, _ = json.Marshal(long)
	if _, e := decodeImportedTLSPreparation(large); e == nil {
		t.Fatal("oversized chain accepted")
	}
	for _, bad := range []string{"null", "[]", valid + "{}", strings.Replace(valid, "tenant_id", "Tenant_ID", 1), strings.Replace(valid, `"tenant_id":`, `"tenant_id":"`+id+`","tenant_id":`, 1), strings.Replace(valid, `"domain":`, `"private_key":"secret","domain":`, 1), strings.Replace(valid, `"fullchain_pem":"synthetic-public-chain"`, `"fullchain_pem":null`, 1), strings.Replace(valid, id, "invalid", 1), strings.Replace(valid, req.AdoptionSHA256, "missing", 1), strings.Repeat(" ", 96<<10) + valid} {
		if _, e := decodeImportedTLSPreparation([]byte(bad)); e == nil {
			t.Fatal("ambiguous or unsupported request accepted")
		}
	}
	app := &application{adminToken: "synthetic-imported-tls-owner"}
	mux := http.NewServeMux()
	app.registerRemnawaveRoutes(mux)
	for _, kind := range []string{"anonymous", "admin", "monitor", "tenant", "mode", "digest", "body", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			body := valid
			if kind == "body" {
				body = `{"private_key":"never echo this"}`
			}
			if kind == "oversized" {
				body = strings.Repeat(" ", 96<<10) + valid
			}
			r := httptest.NewRequest("POST", "/api/v1/remnawave/imports/"+id+"/prepare-tls", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+app.adminToken)
			r.Header.Set("X-Remnawave-Mode", "prepare-held-tls")
			r.Header.Set("X-Reviewed-Inventory-SHA256", strings.Repeat("b", 64))
			want := 400
			switch kind {
			case "anonymous":
				r.Header.Del("Authorization")
				want = 401
			case "admin", "monitor":
				r = r.WithContext(store.WithAdminPrincipal(r.Context(), model.AdminSession{Account: model.AdminAccount{Role: kind}}))
				want = 403
			case "tenant":
				r.Header.Set("Authorization", "Bearer vpt1_synthetic")
				want = 401
			case "mode":
				r.Header.Set("X-Remnawave-Mode", "activate")
			case "digest":
				r.Header.Del("X-Reviewed-Inventory-SHA256")
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != want || strings.Contains(w.Body.String(), "never echo this") {
				t.Fatal("authorization, input rejection or response redaction failed")
			}
		})
	}
}
