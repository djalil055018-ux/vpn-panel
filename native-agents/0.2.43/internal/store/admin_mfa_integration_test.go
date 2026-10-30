//go:build integration

package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"vpn-platform/internal/security"
)

func TestAdminMFALifecycleReplayAndRollbackIntegration(t *testing.T) {
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
	var database string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	password := "mfa-fixture-password-0001"
	hash, err := security.HashPassword(password)
	check(err)
	account, err := p.CreateAdminAccount(ctx, fmt.Sprintf("mfa-fixture-%d", time.Now().UnixNano()), "owner", hash)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM admin_accounts WHERE id=$1::uuid`, account.ID)
	tokenHash := security.HashToken("mfa-fixture-original-session")
	session, err := p.CreateAdminSession(ctx, account.ID, hash, "", tokenHash)
	check(err)
	scoped := WithAdminPrincipal(ctx, session)
	master := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	enrollment, err := p.BeginOwnAdminMFA(scoped, hash, master)
	check(err)
	if enrollment.Secret == "" || !strings.HasPrefix(enrollment.ProvisioningURL, "otpauth://totp/") {
		t.Fatal("enrollment missing")
	}
	state, err := p.OwnAdminMFAStatus(scoped)
	check(err)
	if state.Enabled || state.PendingExpiresAt == nil {
		t.Fatal("MFA enabled before confirmation")
	}
	if _, err = p.ConfirmOwnAdminMFA(scoped, hash, "not-otp", master); !errors.Is(err, ErrAdminMFAInvalid) {
		t.Fatal("bad confirmation accepted")
	}
	// Confirm with the previous accepted step; the current step remains available
	// for the concurrent login proof without sleeping through a TOTP window.
	code, err := security.TOTPCode(enrollment.Secret, time.Now().Unix()/30-1)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE admin_mfa SET pending_expires_at=now()-interval '1 second' WHERE account_id=$1::uuid`, account.ID)
	check(err)
	if _, err = p.ConfirmOwnAdminMFA(scoped, hash, code, master); !errors.Is(err, ErrAdminMFAInvalid) {
		t.Fatal("expired enrollment accepted")
	}
	enrollment, err = p.BeginOwnAdminMFA(scoped, hash, master)
	check(err)
	_, err = p.RevokeOwnAdminSessions(scoped, "")
	check(err)
	tokenHash = security.HashToken("mfa-fixture-after-revoke-all")
	session, err = p.CreateAdminSession(ctx, account.ID, hash, "", tokenHash)
	check(err)
	scoped = WithAdminPrincipal(ctx, session)
	code, err = security.TOTPCode(enrollment.Secret, time.Now().Unix()/30-1)
	check(err)
	if _, err = p.ConfirmOwnAdminMFA(scoped, hash, code, master); !errors.Is(err, ErrAdminMFAInvalid) {
		t.Fatal("enrollment from revoked security version accepted")
	}
	enrollment, err = p.BeginOwnAdminMFA(scoped, hash, master)
	check(err)
	code, err = security.TOTPCode(enrollment.Secret, time.Now().Unix()/30-1)
	check(err)

	if _, err = p.ConfirmOwnAdminMFA(scoped, hash, code, master, "invalid-session-hash"); err == nil {
		t.Fatal("invalid replacement session committed MFA")
	}
	state, err = p.OwnAdminMFAStatus(scoped)
	check(err)
	if state.Enabled {
		t.Fatal("failed session replacement partially enabled MFA")
	}
	codes, err := p.ConfirmOwnAdminMFA(scoped, hash, code, master)
	check(err)
	if len(codes) != 10 {
		t.Fatal("recovery codes missing")
	}
	if _, err = p.AuthenticateAdminSession(ctx, tokenHash); !errors.Is(err, ErrNotFound) {
		t.Fatal("pre-MFA session survived")
	}
	_, stored, err := p.AdminLoginRecord(ctx, account.Username)
	check(err)
	if stored != "mfa$"+hash || security.VerifyPassword(password, stored) {
		t.Fatal("old verifier could bypass MFA marker")
	}
	// Model the actual old binary's password reset statement. The additive schema
	// must reject it instead of silently disabling the second factor after rollback.
	if _, err = p.Pool.Exec(ctx, `UPDATE admin_accounts SET password_hash=$2 WHERE id=$1::uuid`, account.ID, hash); err == nil {
		t.Fatal("old reset bypassed MFA constraint")
	}
	if _, err = p.CreateAdminSession(ctx, account.ID, stored, "", security.HashToken("without-factor")); !errors.Is(err, ErrAdminMFAInvalid) {
		t.Fatal("password-only session allowed")
	}
	code, err = security.TOTPCode(enrollment.Secret, time.Now().Unix()/30)
	check(err)
	if _, err = p.CreateAdminSessionWithMFA(ctx, account.ID, stored, "", security.HashToken("missing-mfa-key"), code, "", ""); err == nil {
		t.Fatal("missing key accepted TOTP")
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := p.CreateAdminSessionWithMFA(ctx, account.ID, stored, "", security.HashToken(fmt.Sprintf("mfa-concurrent-%d", i)), code, "", master)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, ErrAdminMFAInvalid) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatal("TOTP replay under concurrent login")
	}
	if _, err = p.CreateAdminSessionWithMFA(ctx, account.ID, stored, "", "invalid-token-hash", "", codes[0], master); err == nil {
		t.Fatal("invalid session hash committed recovery consumption")
	}
	recovered, err := p.CreateAdminSessionWithMFA(ctx, account.ID, stored, "", security.HashToken("recovery-first"), "", codes[0], "")
	check(err)
	if _, err = p.CreateAdminSessionWithMFA(ctx, account.ID, stored, "", security.HashToken("recovery-replay"), "", codes[0], master); !errors.Is(err, ErrAdminMFAInvalid) {
		t.Fatal("recovery code replayed")
	}
	recoveredCtx := WithAdminPrincipal(ctx, recovered)
	state, err = p.OwnAdminMFAStatus(recoveredCtx)
	check(err)
	if !state.Enabled || state.RecoveryCodesRemaining != 9 {
		t.Fatal("recovery consumption not persisted")
	}
	if _, err = p.BeginOwnAdminMFA(recoveredCtx, stored, master); !errors.Is(err, ErrAdminConflict) {
		t.Fatal("enabled factor silently replaced")
	}
	rotated, err := p.RotateOwnAdminRecoveryCodes(recoveredCtx, stored, "", codes[1], master)
	check(err)
	if _, err = p.AuthenticateAdminSession(ctx, security.HashToken("recovery-first")); !errors.Is(err, ErrNotFound) {
		t.Fatal("recovery rotation kept old session")
	}
	if _, err = p.CreateAdminSessionWithMFA(ctx, account.ID, stored, "", security.HashToken("old-recovery"), "", codes[2], master); !errors.Is(err, ErrAdminMFAInvalid) {
		t.Fatal("old recovery set retained")
	}
	fresh, err := p.CreateAdminSessionWithMFA(ctx, account.ID, stored, "", security.HashToken("new-recovery"), "", rotated[0], master)
	check(err)
	newer, err := security.HashPassword("mfa-fixture-password-0002")
	check(err)
	_, err = p.UpdateAdminAccount(ctx, account.ID, nil, nil, &newer)
	check(err)
	_, stored, err = p.AdminLoginRecord(ctx, account.Username)
	check(err)
	if stored != "mfa$"+newer {
		t.Fatal("password reset removed MFA")
	}
	if err = p.DisableOwnAdminMFA(WithAdminPrincipal(ctx, fresh), stored, "", rotated[1], master); err == nil {
		t.Fatal("revoked session changed MFA")
	}
	fresh, err = p.CreateAdminSessionWithMFA(ctx, account.ID, stored, "", security.HashToken("after-password-reset"), "", rotated[1], master)
	check(err)
	check(p.DisableOwnAdminMFA(WithAdminPrincipal(ctx, fresh), stored, "", rotated[2], master))
	_, stored, err = p.AdminLoginRecord(ctx, account.Username)
	check(err)
	if stored != newer {
		t.Fatal("disable did not restore standard password verifier")
	}
	_, err = p.CreateAdminSession(ctx, account.ID, stored, "", security.HashToken("after-disable"))
	check(err)
}
