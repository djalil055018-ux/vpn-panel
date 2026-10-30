// verify-restored-mfa checks encrypted factors only in a read-only restore clone.
// It never emits identities, keys, ciphertexts, OTPs or recovery hashes.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"regexp"
	"time"
	"vpn-platform/internal/security"
)

var errVerification = errors.New("restored MFA verification failed")
var restoreDatabase = regexp.MustCompile(`^vpn_restore_drill_[0-9a-f]{16}$`)

type report struct {
	Status             string `json:"status"`
	EnabledAccounts    int    `json:"enabled_accounts"`
	PendingEnrollments int    `json:"pending_enrollments"`
	KeyConfigured      bool   `json:"key_configured"`
}
type factorRow struct {
	ID                       string
	Enabled, Marked, Present bool
	Current, Pending         string
	PendingActive            bool
}

func checkDatabase(name, readOnly string) error {
	if !restoreDatabase.MatchString(name) || readOnly != "on" {
		return errVerification
	}
	return nil
}
func verifyRow(master string, row factorRow) (int, int, error) {
	if row.Enabled != row.Marked || row.Enabled && (!row.Present || row.Current == "") || !row.Enabled && row.Current != "" {
		return 0, 0, errVerification
	}
	current, pending := 0, 0
	for _, entry := range []struct {
		active    bool
		encrypted string
		pending   bool
	}{{row.Enabled, row.Current, false}, {row.PendingActive, row.Pending, true}} {
		if !entry.active {
			continue
		}
		if !row.Present {
			return 0, 0, errVerification
		}
		secret, err := security.OpenMFASecret(master, row.ID, entry.encrypted)
		if err != nil {
			return 0, 0, errVerification
		}
		if _, err = security.TOTPCode(secret, 0); err != nil {
			return 0, 0, errVerification
		}
		if entry.pending {
			pending++
		} else {
			current++
		}
	}
	return current, pending, nil
}
func verify(ctx context.Context, dsn, master string) (report, error) {
	out := report{Status: "verified", KeyConfigured: security.MFAKeyReady(master)}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return report{}, errVerification
	}
	local := func(host string) bool { return host == "127.0.0.1" || host == "::1" || host == "localhost" }
	if !local(cfg.Host) || !restoreDatabase.MatchString(cfg.Database) {
		return report{}, errVerification
	}
	for _, fallback := range cfg.Fallbacks {
		if !local(fallback.Host) {
			return report{}, errVerification
		}
	}
	cfg.ConnectTimeout = 5 * time.Second
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return report{}, errVerification
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return report{}, errVerification
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var name, readOnly string
	if err = tx.QueryRow(ctx, `SELECT current_database(),current_setting('default_transaction_read_only')`).Scan(&name, &readOnly); err != nil || checkDatabase(name, readOnly) != nil {
		return report{}, errVerification
	}
	rows, err := tx.Query(ctx, `SELECT a.id::text,a.mfa_enabled,left(a.password_hash,4)='mfa$',m.account_id IS NOT NULL,COALESCE(m.secret_ciphertext,''),COALESCE(m.pending_ciphertext,''),COALESCE(m.pending_expires_at>now() AND m.pending_security_version=a.security_version,false) FROM admin_accounts a LEFT JOIN admin_mfa m ON m.account_id=a.id ORDER BY a.id`)
	if err != nil {
		return report{}, errVerification
	}
	defer rows.Close()
	for rows.Next() {
		var row factorRow
		if err = rows.Scan(&row.ID, &row.Enabled, &row.Marked, &row.Present, &row.Current, &row.Pending, &row.PendingActive); err != nil {
			return report{}, errVerification
		}
		current, pending, err := verifyRow(master, row)
		if err != nil {
			return report{}, errVerification
		}
		out.EnabledAccounts += current
		out.PendingEnrollments += pending
	}
	if rows.Err() != nil {
		return report{}, errVerification
	}
	return out, nil
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := verify(ctx, os.Getenv("DATABASE_URL"), os.Getenv("ADMIN_MFA_ENCRYPTION_KEY"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "RESTORED_MFA_VERIFICATION_FAILED")
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
}
