//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestAdministratorLifecycleIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(90*time.Second))
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
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM admin_accounts`).Scan(&count))
	if count != 0 {
		t.Fatal("test requires empty admin tables")
	}
	defer p.Pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE username LIKE 'codex-admin-%'`)
	hash, err := security.HashPassword("fixture-admin-password-001")
	check(err)
	newer, err := security.HashPassword("fixture-admin-password-002")
	check(err)
	owner, err := p.BootstrapAdminOwner(ctx, "codex-admin-owner", hash)
	check(err)
	if owner == nil || owner.Role != "owner" {
		t.Fatal("bootstrap owner missing")
	}
	same, err := p.BootstrapAdminOwner(ctx, "codex-admin-owner", newer)
	check(err)
	_, stored, err := p.AdminLoginRecord(ctx, owner.Username)
	check(err)
	if same.ID != owner.ID || stored != hash {
		t.Fatal("bootstrap reset existing account")
	}
	other, err := p.BootstrapAdminOwner(ctx, "codex-admin-other", hash)
	check(err)
	if other != nil {
		t.Fatal("bootstrap added account after initialization")
	}
	_, err = p.CreateAdminAccount(ctx, "CODEX-ADMIN-OWNER", "owner", hash)
	if !errors.Is(err, ErrAdminConflict) {
		t.Fatal("case insensitive uniqueness absent")
	}
	enabled := false
	adminRole := "admin"
	_, err = p.UpdateAdminAccount(ctx, owner.ID, nil, &enabled, nil)
	if !errors.Is(err, ErrLastOwner) {
		t.Fatal("last owner disabled")
	}
	_, err = p.UpdateAdminAccount(ctx, owner.ID, &adminRole, nil, nil)
	if !errors.Is(err, ErrLastOwner) {
		t.Fatal("last owner demoted")
	}
	monitor, err := p.CreateAdminAccount(ctx, "codex-admin-monitor", "monitor", hash)
	check(err)
	session, err := p.CreateAdminSession(ctx, monitor.ID, hash, "", security.HashToken("test-session-one"))
	check(err)
	scoped := WithAdminPrincipal(ctx, session)
	_, err = p.ListAdminAccounts(scoped)
	if !errors.Is(err, ErrAdminPermission) {
		t.Fatal("monitor listed accounts")
	}
	_, err = p.CreateAdminAccount(scoped, "codex-admin-escape", "owner", hash)
	if !errors.Is(err, ErrAdminPermission) {
		t.Fatal("monitor created owner")
	}
	tenant := WithTenantPrincipal(ctx, model.TenantAPIToken{Role: "reseller"})
	_, err = p.ListAdminAccounts(tenant)
	if !errors.Is(err, ErrAdminPermission) {
		t.Fatal("tenant listed accounts")
	}
	_, err = p.AuthenticateAdminSession(ctx, "test-session-one")
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("unhashed session accepted")
	}
	authenticated, err := p.AuthenticateAdminSession(ctx, security.HashToken("test-session-one"))
	check(err)
	if authenticated.Account.ID != monitor.ID || authenticated.Account.Role != "monitor" {
		t.Fatal("wrong session principal")
	}
	check(p.RecordAdminMutationIntent(scoped, "PUT", "/api/v1/admin/me/password"))
	var actor string
	check(p.Pool.QueryRow(ctx, `SELECT actor_id FROM audit_events WHERE event_type='admin_request.started' AND actor_id=$1 ORDER BY created_at DESC LIMIT 1`, monitor.ID).Scan(&actor))
	check(p.ChangeOwnAdminPassword(scoped, hash, newer))
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("test-session-one"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("password change retained session")
	}
	_, err = p.CreateAdminSession(ctx, monitor.ID, hash, "", security.HashToken("stale-login"))
	if !errors.Is(err, ErrAdminConflict) {
		t.Fatal("stale password verification minted session")
	}
	session, err = p.CreateAdminSession(ctx, monitor.ID, newer, "", security.HashToken("test-session-two"))
	check(err)
	_, err = p.UpdateAdminAccount(ctx, monitor.ID, &adminRole, nil, nil)
	check(err)
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("test-session-two"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("role change retained session")
	}
	session, err = p.CreateAdminSession(ctx, monitor.ID, newer, "", security.HashToken("test-session-three"))
	check(err)
	check(p.RevokeAdminSession(WithAdminPrincipal(ctx, session), session.ID))
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("test-session-three"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("logout retained session")
	}
	session, err = p.CreateAdminSession(ctx, monitor.ID, newer, "", security.HashToken("test-session-expired"))
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE admin_sessions SET created_at=now()-interval '10 hours',expires_at=now()-interval '1 hour' WHERE id=$1::uuid`, session.ID)
	check(err)
	_, err = p.AuthenticateAdminSession(ctx, security.HashToken("test-session-expired"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("expired session accepted")
	}
	_, err = p.UpdateAdminAccount(ctx, monitor.ID, nil, &enabled, nil)
	check(err)
	_, _, err = p.AdminLoginRecord(ctx, monitor.Username)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled login found")
	}
	_, err = p.CreateAdminSession(ctx, monitor.ID, newer, "", security.HashToken("disabled-login"))
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("disabled account minted session")
	}
	owner2, err := p.CreateAdminAccount(ctx, "codex-admin-owner2", "owner", hash)
	check(err)
	// Both requests start with two owners. Serialization must permit exactly one.
	results := make(chan error, 2)
	for _, id := range []string{owner.ID, owner2.ID} {
		go func(id string) { _, err := p.UpdateAdminAccount(ctx, id, &adminRole, nil, nil); results <- err }(id)
	}
	a, b := <-results, <-results
	if !((a == nil && errors.Is(b, ErrLastOwner)) || (b == nil && errors.Is(a, ErrLastOwner))) {
		t.Fatalf("concurrent owner protection: %v / %v", a, b)
	}
}
