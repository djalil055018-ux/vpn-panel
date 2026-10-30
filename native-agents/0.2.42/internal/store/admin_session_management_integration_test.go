//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/security"
)

func TestAdminSessionScopeIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(60*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("clone connection failed")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	hash, err := security.HashPassword("fixture-sessions-password-001")
	check(err)
	owner, err := p.CreateAdminAccount(ctx, "codex-session-owner", "owner", hash)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE username IN('codex-session-owner','codex-session-monitor')`)
	monitor, err := p.CreateAdminAccount(ctx, "codex-session-monitor", "monitor", hash)
	check(err)
	first, err := p.CreateAdminSession(ctx, owner.ID, hash, "", security.HashToken("session-first"))
	check(err)
	second, err := p.CreateAdminSession(ctx, owner.ID, hash, "", security.HashToken("session-second"))
	check(err)
	foreign, err := p.CreateAdminSession(ctx, monitor.ID, hash, "", security.HashToken("session-foreign"))
	check(err)
	scoped := WithAdminPrincipal(ctx, first)
	list, err := p.ListOwnAdminSessions(scoped)
	check(err)
	if len(list) != 2 {
		t.Fatal("session list crossed account boundary")
	}
	current := 0
	for _, s := range list {
		if s.Current {
			current++
			if s.ID != first.ID {
				t.Fatal("wrong current session")
			}
		}
	}
	if current != 1 {
		t.Fatal("current session not marked")
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), "token") || strings.Contains(string(raw), "hash") || strings.Contains(string(raw), foreign.ID) {
		t.Fatal("session response disclosed credentials or foreign session")
	}
	_, err = p.ListOwnAdminSessions(ctx)
	if !errors.Is(err, ErrAdminPermission) {
		t.Fatal("root context listed personal sessions")
	}
	_, err = p.RevokeOwnAdminSessions(scoped, foreign.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign session revoked")
	}
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("session-foreign"))
	check(err)
	n, err := p.RevokeOwnAdminSessions(scoped, second.ID)
	check(err)
	if n != 1 {
		t.Fatal("wrong revoke count")
	}
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("session-second"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("single revoke retained session")
	}
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("session-first"))
	check(err)
	// Login retention is bounded even before expired-session cleanup runs.
	for i := 0; i < 24; i++ {
		_, err = p.CreateAdminSession(ctx, owner.ID, hash, "", security.HashToken(fmt.Sprintf("session-cap-%d", i)))
		check(err)
	}
	latest, err := p.AuthenticateAdminSession(ctx, security.HashToken("session-cap-23"))
	check(err)
	scoped = WithAdminPrincipal(ctx, latest)
	list, err = p.ListOwnAdminSessions(scoped)
	check(err)
	if len(list) != 20 {
		t.Fatalf("retention cap %d", len(list))
	}
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("session-cap-0"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("old session survived retention cap")
	}
	n, err = p.RevokeOwnAdminSessions(scoped, "")
	check(err)
	if n != 20 {
		t.Fatal("revoke all missed sessions")
	}
	list, err = p.ListOwnAdminSessions(scoped)
	check(err)
	if len(list) != 0 {
		t.Fatal("sessions remain after revoke all")
	}
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("session-cap-23"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("revoke all retained current session")
	}
	account, _, err := p.AdminLoginRecord(ctx, owner.Username)
	check(err)
	if account.SecurityVersion != owner.SecurityVersion+1 {
		t.Fatal("revoke all did not invalidate legacy bridge")
	}
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("session-foreign"))
	check(err)
	_, err = p.RevokeOwnAdminSessions(WithAdminPrincipal(ctx, foreign), foreign.ID)
	check(err)
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("session-foreign"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("monitor could not revoke own current session")
	}
}
