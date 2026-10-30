package main

import (
	"context"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/security"
)

func TestVerifyRestoredFactors(t *testing.T) {
	master, _ := security.NewToken(32)
	other, _ := security.NewToken(32)
	secret, _ := security.NewTOTPSecret()
	encrypted, _ := security.SealMFASecret(master, "account-a", secret)
	valid := factorRow{ID: "account-a", Enabled: true, Marked: true, Present: true, Current: encrypted}
	a, b, err := verifyRow(master, valid)
	if err != nil || a != 1 || b != 0 {
		t.Fatal("valid factor rejected")
	}
	for _, key := range []string{"", other} {
		if _, _, err := verifyRow(key, valid); err == nil {
			t.Fatal("wrong key accepted")
		}
	}
	for _, mutation := range []func(*factorRow){
		func(r *factorRow) { r.ID = "account-b" }, func(r *factorRow) { r.Current = "corrupt" }, func(r *factorRow) { r.Current = "" },
		func(r *factorRow) { r.Present = false }, func(r *factorRow) { r.Marked = false }, func(r *factorRow) { r.Enabled = false; r.Marked = false },
	} {
		r := valid
		mutation(&r)
		if _, _, err := verifyRow(master, r); err == nil {
			t.Fatal("invalid persisted state accepted")
		}
	}
	pending := factorRow{ID: "account-a", Present: true, Pending: encrypted, PendingActive: true}
	a, b, err = verifyRow(master, pending)
	if err != nil || a != 0 || b != 1 {
		t.Fatal("active enrollment rejected")
	}
	pending.Pending = "expired-corrupt"
	pending.PendingActive = false
	if _, _, err = verifyRow(master, pending); err != nil {
		t.Fatal("inactive enrollment should not gate restore")
	}
	malformed, _ := security.SealMFASecret(master, "account-a", "not-a-totp-secret")
	valid.Current = malformed
	if _, _, err = verifyRow(master, valid); err == nil {
		t.Fatal("authenticated malformed TOTP accepted")
	}
	if _, _, err = verifyRow("", factorRow{ID: "never-enrolled"}); err != nil {
		t.Fatal("unenrolled account needs no key")
	}
}
func TestRestoreDatabaseGuard(t *testing.T) {
	if checkDatabase("vpn_restore_drill_0123456789abcdef", "on") != nil {
		t.Fatal("clone rejected")
	}
	for _, name := range []string{"vpn_platform", "postgres", "vpn_restore_drill_../escape", "vpn_restore_drill_0123456789abcdef_extra"} {
		if checkDatabase(name, "on") == nil {
			t.Fatal("non-clone accepted")
		}
	}
	if checkDatabase("vpn_restore_drill_0123456789abcdef", "off") == nil {
		t.Fatal("writable clone accepted")
	}
}

func TestRestoredMFAReadOnlyCloneIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("test database not configured")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || cfg.Database != "vpn_codex_test_usage_full_20260908" {
		t.Fatal("explicit disposable source required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("test connection failed")
	}
	defer admin.Close(context.Background())
	id, err := security.NewToken(16)
	if err != nil {
		t.Fatal("random fixture failed")
	}
	// Hashing yields a safe fixed hex suffix rather than interpolating a DSN/name.
	name := "vpn_restore_drill_" + security.HashToken(id)[:16]
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal("clone create failed")
	}
	defer func() {
		if _, err = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Error("clone cleanup failed")
		}
	}()
	cloneURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("test DSN invalid")
	}
	cloneURL.Path = "/" + name
	cloneDSN := cloneURL.String()
	cloneCfg := cfg.Copy()
	cloneCfg.Database = name
	clone, err := pgx.ConnectConfig(ctx, cloneCfg)
	if err != nil {
		t.Fatal("clone connect failed")
	}
	defer clone.Close(context.Background())
	_, err = clone.Exec(ctx, `CREATE TABLE admin_accounts(id text PRIMARY KEY,mfa_enabled boolean,password_hash text,security_version bigint); CREATE TABLE admin_mfa(account_id text,secret_ciphertext text,pending_ciphertext text,pending_expires_at timestamptz,pending_security_version bigint);`)
	if err != nil {
		t.Fatal("fixture schema failed")
	}
	master, _ := security.NewToken(32)
	secret, _ := security.NewTOTPSecret()
	encrypted, _ := security.SealMFASecret(master, "fixture-a", secret)
	_, err = clone.Exec(ctx, `INSERT INTO admin_accounts VALUES('fixture-a',true,'mfa$placeholder',1),('fixture-b',false,'placeholder',1)`)
	if err != nil {
		t.Fatal("fixture account failed")
	}
	_, err = clone.Exec(ctx, `INSERT INTO admin_mfa(account_id,secret_ciphertext) VALUES('fixture-a',$1)`, encrypted)
	if err != nil {
		t.Fatal("fixture factor failed")
	}
	if _, err = verify(ctx, cloneDSN, master); err == nil {
		t.Fatal("writable DB accepted")
	}
	if _, err = admin.Exec(ctx, "ALTER DATABASE "+name+" SET default_transaction_read_only=on"); err != nil {
		t.Fatal("read-only guard failed")
	}
	result, err := verify(ctx, cloneDSN, master)
	if err != nil || result.EnabledAccounts != 1 || result.PendingEnrollments != 0 {
		t.Fatal("read-only encrypted clone verification failed")
	}
	if _, err = verify(ctx, cloneDSN, ""); err == nil {
		t.Fatal("missing key accepted")
	}
	other, _ := security.NewToken(32)
	if _, err = verify(ctx, cloneDSN, other); err == nil {
		t.Fatal("wrong key accepted")
	}
	// Existing setup connection predates the read-only default and is test-only.
	if _, err = clone.Exec(ctx, `UPDATE admin_mfa SET secret_ciphertext='corrupt' WHERE account_id='fixture-a'`); err != nil {
		t.Fatal("corruption fixture failed")
	}
	if _, err = verify(ctx, cloneDSN, master); err == nil {
		t.Fatal("corrupt ciphertext accepted")
	}
	if _, err = clone.Exec(ctx, `DELETE FROM admin_mfa`); err != nil {
		t.Fatal("orphan fixture failed")
	}
	if _, err = verify(ctx, cloneDSN, master); err == nil {
		t.Fatal("missing MFA row accepted")
	}
	if _, err = verify(ctx, dsn, master); err == nil || strings.Contains(err.Error(), master) {
		t.Fatal("non-restore DB accepted or sensitive error")
	}
}
