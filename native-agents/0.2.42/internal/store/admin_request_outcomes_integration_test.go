//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestAdminRequestOutcomesIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(30*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("test database unavailable")
	}
	defer p.Close()
	var db, actor, foreign string
	if p.Pool.QueryRow(ctx, `SELECT current_database(),gen_random_uuid()::text,gen_random_uuid()::text`).Scan(&db, &actor, &foreign) != nil || !strings.HasPrefix(db, "vpn_codex_test_audit87_") {
		t.Fatal("isolated audit database required")
	}
	defer p.Pool.Exec(context.Background(), `DELETE FROM audit_events WHERE actor_id=$1`, actor)
	principal := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{ID: actor, Role: "admin"}})
	other := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{ID: foreign, Role: "admin"}})
	if _, err = p.BeginAdminMutation(ctx, "POST", "POST /api/v1/nodes"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unauthenticated intent accepted")
	}
	id, err := p.BeginAdminMutation(principal, "POST", "POST /api/v1/nodes/{id}")
	if err != nil {
		t.Fatal("intent failed")
	}
	if err = p.CompleteAdminMutation(other, id, 202, true); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign actor completed request")
	}
	if err = p.CompleteAdminMutation(principal, id, 777, true); !errors.Is(err, ErrAdminConflict) {
		t.Fatal("invalid HTTP status accepted")
	}
	if err = p.CompleteAdminMutation(principal, id, 202, true); err != nil {
		t.Fatal("receipt failed")
	}
	interrupted, err := p.BeginAdminMutation(principal, "DELETE", "DELETE /api/v1/nodes/{id}")
	if err != nil {
		t.Fatal("second intent failed")
	}
	if err = p.CompleteAdminMutation(principal, interrupted, 0, false); err != nil {
		t.Fatal("interruption receipt failed")
	}
	history, err := p.AuditHistory(ctx, "", "admin_request.completed", "admin_account", nil, 100)
	if err != nil {
		t.Fatal("history failed")
	}
	seen := map[string]model.AuditEventMetadata{}
	for _, e := range history.Events {
		if e.ActorID != nil && *e.ActorID == actor && e.RequestID != nil {
			seen[*e.RequestID] = e
		}
	}
	accepted := seen[id]
	aborted := seen[interrupted]
	if len(seen) != 2 || accepted.HTTPStatus == nil || *accepted.HTTPStatus != 202 || accepted.RequestOutcome == nil || *accepted.RequestOutcome != "responded" || aborted.HTTPStatus != nil || aborted.RequestOutcome == nil || *aborted.RequestOutcome != "interrupted" {
		t.Fatal("incorrect safe outcome metadata")
	}
	// Legacy/malformed payloads must never enter the public metadata projection.
	for _, payload := range []string{
		`{"request_id":"SECRET-NEVER-RETURN","outcome":"SECRET-NEVER-RETURN","http_status":"SECRET-NEVER-RETURN"}`,
		`{"request_id":"00000000-0000-4000-8000-000000000001","outcome":"responded","http_status":1e100}`,
		`{"request_id":"00000000-0000-4000-8000-000000000001","outcome":"responded","http_status":"200"}`,
	} {
		if _, err = p.Pool.Exec(ctx, `INSERT INTO audit_events(event_type,actor_type,actor_id,payload) VALUES('admin_request.completed','admin_account',$1,$2::jsonb)`, actor, payload); err != nil {
			t.Fatal("malformed fixture failed")
		}
	}
	history, err = p.AuditHistory(ctx, "", "admin_request.completed", "admin_account", nil, 100)
	if err != nil {
		t.Fatal("malformed payload broke history")
	}
	raw, err := json.Marshal(history)
	if err != nil || strings.Contains(string(raw), "SECRET-NEVER-RETURN") {
		t.Fatal("history leaked payload")
	}
	for _, e := range history.Events {
		if e.ActorID != nil && *e.ActorID == actor && e.RequestID != nil && *e.RequestID != id && *e.RequestID != interrupted {
			t.Fatal("malformed receipt exposed")
		}
	}
	var started int
	if p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor_id=$1 AND event_type='admin_request.started'`, actor).Scan(&started) != nil || started != 2 {
		t.Fatal("intent was rewritten or removed")
	}
}
