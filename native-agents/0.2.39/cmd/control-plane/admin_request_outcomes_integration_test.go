//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestAdminRequestOutcomesHTTPIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	p, err := store.NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("isolated database unavailable")
	}
	defer p.Close()
	var db, suffix string
	if p.Pool.QueryRow(ctx, `SELECT current_database(),gen_random_uuid()::text`).Scan(&db, &suffix) != nil || !strings.HasPrefix(db, "vpn_codex_test_audit87_") {
		t.Fatal("isolated audit database required")
	}
	hash, err := security.HashPassword("audit-fixture-password-012345")
	if err != nil {
		t.Fatal("fixture hashing failed")
	}
	owner, err := p.CreateAdminAccount(ctx, "codex87-owner-"+suffix, "owner", hash)
	if err != nil {
		t.Fatal("fixture owner failed")
	}
	defer p.Pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id=$1::uuid`, owner.ID)
	defer p.Pool.Exec(context.Background(), `DELETE FROM audit_events WHERE actor_id=$1`, owner.ID)
	app := application{store: p, adminToken: "fixture-root-never-return"}
	mux := http.NewServeMux()
	mutations := 0
	mux.HandleFunc("POST /api/v1/codex-audit/{id}", app.requireAdmin(func(w http.ResponseWriter, r *http.Request) { mutations++; w.WriteHeader(202) }))
	mux.HandleFunc("DELETE /api/v1/codex-audit/{id}", app.requireAdmin(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	for _, role := range []string{"admin", "monitor"} {
		account, err := p.CreateAdminAccount(ctx, "codex87-"+role+"-"+suffix, role, hash)
		if err != nil {
			t.Fatal("fixture account failed")
		}
		defer p.Pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id=$1::uuid`, account.ID)
		defer p.Pool.Exec(context.Background(), `DELETE FROM audit_events WHERE actor_id=$1`, account.ID)
		entropy := make([]byte, 32)
		if _, err = rand.Read(entropy); err != nil {
			t.Fatal("fixture entropy failed")
		}
		token := "vpa1_" + base64.RawURLEncoding.EncodeToString(entropy)
		if _, err = p.CreateAdminSession(ctx, account.ID, hash, "", security.HashToken(token)); err != nil {
			t.Fatal("fixture session failed")
		}
		for _, method := range []string{"POST", "DELETE"} {
			request := httptest.NewRequest(method, "/api/v1/codex-audit/SECRET-NEVER-RETURN?private=SECRET-NEVER-RETURN", nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			expected := 202
			if method == "DELETE" {
				expected = 400
			}
			if role == "monitor" {
				expected = 403
			}
			if response.Code != expected {
				t.Fatalf("unexpected HTTP outcome %d", response.Code)
			}
		}
		var total int
		if p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor_id=$1 AND event_type='admin_request.completed'`, account.ID).Scan(&total) != nil || total != 2 {
			t.Fatal("missing authenticated HTTP receipts")
		}
		var leaked bool
		if p.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE actor_id=$1 AND (payload::text LIKE '%SECRET-NEVER-RETURN%' OR payload::text LIKE '%'||$2::text||'%'))`, account.ID, token).Scan(&leaked) != nil || leaked {
			t.Fatal("request secret entered audit")
		}
		var expectedCode int
		expectedCode = 202
		if role == "monitor" {
			expectedCode = 403
		}
		var found bool
		if p.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events done JOIN audit_events started ON started.id::text=done.payload->>'request_id' WHERE done.actor_id=$1 AND done.event_type='admin_request.completed' AND started.payload->>'method'='POST' AND (done.payload->>'http_status')::int=$2::int AND done.payload->>'outcome'='responded')`, account.ID, expectedCode).Scan(&found) != nil || !found {
			t.Fatal("HTTP result not correlated with intent")
		}
	}
	if mutations != 1 {
		t.Fatal("monitor mutation was executed")
	}
}
