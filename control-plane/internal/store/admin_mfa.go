package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

var ErrAdminMFAInvalid = errors.New("invalid second factor")

// Explicitly unwrap only for password verification. Session creation separately
// enforces MFA under the same row lock as consumption of the one-time factor.
func AdminPasswordForVerification(hash string) string { return strings.TrimPrefix(hash, "mfa$") }

type AdminMFAStatus struct {
	Enabled                bool       `json:"enabled"`
	PendingExpiresAt       *time.Time `json:"pending_expires_at"`
	RecoveryCodesRemaining int        `json:"recovery_codes_remaining"`
}
type AdminMFAEnrollment struct {
	Secret          string    `json:"secret"`
	ProvisioningURL string    `json:"provisioning_url"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (p *Postgres) OwnAdminMFAStatus(ctx context.Context) (AdminMFAStatus, error) {
	var out AdminMFAStatus
	s, ok := AdminPrincipal(ctx)
	if !ok {
		return out, ErrAdminPermission
	}
	err := p.Pool.QueryRow(ctx, `SELECT a.mfa_enabled,CASE WHEN m.pending_expires_at>now() AND m.pending_security_version=a.security_version THEN m.pending_expires_at END,COALESCE(cardinality(m.recovery_hashes),0) FROM admin_accounts a LEFT JOIN admin_mfa m ON m.account_id=a.id WHERE a.id=$1::uuid AND a.enabled`, s.Account.ID).Scan(&out.Enabled, &out.PendingExpiresAt, &out.RecoveryCodesRemaining)
	return out, err
}

func lockOwnAdminMFA(ctx context.Context, tx pgx.Tx, verifiedHash string) (model.AdminSession, bool, error) {
	s, ok := AdminPrincipal(ctx)
	if !ok {
		return s, false, ErrAdminPermission
	}
	var hash string
	var version int64
	var enabled bool
	err := tx.QueryRow(ctx, `SELECT password_hash,security_version,mfa_enabled FROM admin_accounts WHERE id=$1::uuid AND enabled FOR UPDATE`, s.Account.ID).Scan(&hash, &version, &enabled)
	if err != nil {
		return s, false, err
	}
	if !security.EqualSecret(hash, verifiedHash) || version != s.Account.SecurityVersion {
		return s, false, ErrAdminConflict
	}
	var live bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM admin_sessions WHERE id=$1::uuid AND account_id=$2::uuid AND expires_at>now())`, s.ID, s.Account.ID).Scan(&live); err != nil {
		return s, false, err
	}
	if !live {
		return s, false, ErrAdminPermission
	}
	return s, enabled, nil
}

func (p *Postgres) BeginOwnAdminMFA(ctx context.Context, verifiedHash, master string) (AdminMFAEnrollment, error) {
	var out AdminMFAEnrollment
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	s, enabled, err := lockOwnAdminMFA(ctx, tx, verifiedHash)
	if err != nil {
		return out, err
	}
	if enabled {
		return out, ErrAdminConflict
	}
	out.Secret, err = security.NewTOTPSecret()
	if err != nil {
		return AdminMFAEnrollment{}, err
	}
	encrypted, err := security.SealMFASecret(master, s.Account.ID, out.Secret)
	if err != nil {
		return AdminMFAEnrollment{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO admin_mfa(account_id,pending_ciphertext,pending_expires_at,pending_security_version) VALUES($1::uuid,$2,now()+interval '10 minutes',$3) ON CONFLICT(account_id) DO UPDATE SET pending_ciphertext=EXCLUDED.pending_ciphertext,pending_expires_at=EXCLUDED.pending_expires_at,pending_security_version=EXCLUDED.pending_security_version,updated_at=now() RETURNING pending_expires_at`, s.Account.ID, encrypted, s.Account.SecurityVersion).Scan(&out.ExpiresAt)
	if err != nil {
		return AdminMFAEnrollment{}, err
	}
	if err = adminAudit(ctx, tx, "admin_mfa.enrollment_started", s.Account.ID, s.Account.Role); err != nil {
		return AdminMFAEnrollment{}, err
	}
	out.ProvisioningURL = security.TOTPProvisioningURL(out.Secret, s.Account.Username)
	if err = tx.Commit(ctx); err != nil {
		return AdminMFAEnrollment{}, err
	}
	return out, nil
}

func (p *Postgres) ConfirmOwnAdminMFA(ctx context.Context, verifiedHash, code, master string, newSessionHash ...string) ([]string, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	s, enabled, err := lockOwnAdminMFA(ctx, tx, verifiedHash)
	if err != nil {
		return nil, err
	}
	if enabled {
		return nil, ErrAdminConflict
	}
	var encrypted string
	err = tx.QueryRow(ctx, `SELECT pending_ciphertext FROM admin_mfa WHERE account_id=$1::uuid AND pending_expires_at>now() AND pending_security_version=$2`, s.Account.ID, s.Account.SecurityVersion).Scan(&encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAdminMFAInvalid
	}
	if err != nil {
		return nil, err
	}
	secret, err := security.OpenMFASecret(master, s.Account.ID, encrypted)
	if err != nil {
		return nil, err
	}
	step, ok := security.VerifyTOTP(secret, code, time.Now(), -1)
	if !ok {
		return nil, ErrAdminMFAInvalid
	}
	codes, hashes, err := security.NewRecoveryCodes(s.Account.ID)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE admin_mfa SET secret_ciphertext=pending_ciphertext,pending_ciphertext=NULL,pending_expires_at=NULL,pending_security_version=NULL,last_totp_step=$2,recovery_hashes=$3,updated_at=now() WHERE account_id=$1::uuid`, s.Account.ID, step, hashes)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE admin_accounts SET mfa_enabled=true,password_hash='mfa$'||password_hash,security_version=security_version+1,updated_at=now() WHERE id=$1::uuid`, s.Account.ID)
	if err != nil {
		return nil, err
	}
	if err = revokeMFAChange(ctx, tx, s, "admin_mfa.enabled", newSessionHash...); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return codes, nil
}

// Caller holds the account row lock. Factor consumption and the authorized
// mutation commit together, preventing replay under concurrent HTTP requests.
func consumeAdminMFA(ctx context.Context, tx pgx.Tx, account model.AdminAccount, code, recovery, master string) error {
	if (code == "") == (recovery == "") {
		return ErrAdminMFAInvalid
	}
	if recovery != "" {
		hash, ok := security.RecoveryCodeHash(account.ID, recovery)
		if !ok {
			return ErrAdminMFAInvalid
		}
		tag, err := tx.Exec(ctx, `UPDATE admin_mfa SET recovery_hashes=array_remove(recovery_hashes,$2),updated_at=now() WHERE account_id=$1::uuid AND secret_ciphertext IS NOT NULL AND $2=ANY(recovery_hashes)`, account.ID, hash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrAdminMFAInvalid
		}
		return adminAudit(WithAdminPrincipal(ctx, model.AdminSession{Account: account}), tx, "admin_mfa.recovery_used", account.ID, account.Role)
	}
	var encrypted string
	var last int64
	err := tx.QueryRow(ctx, `SELECT secret_ciphertext,last_totp_step FROM admin_mfa WHERE account_id=$1::uuid AND secret_ciphertext IS NOT NULL`, account.ID).Scan(&encrypted, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrAdminMFAInvalid
	}
	if err != nil {
		return err
	}
	secret, err := security.OpenMFASecret(master, account.ID, encrypted)
	if err != nil {
		return err
	}
	step, ok := security.VerifyTOTP(secret, code, time.Now(), last)
	if !ok {
		return ErrAdminMFAInvalid
	}
	_, err = tx.Exec(ctx, `UPDATE admin_mfa SET last_totp_step=$2,updated_at=now() WHERE account_id=$1::uuid`, account.ID, step)
	return err
}

func revokeMFAChange(ctx context.Context, tx pgx.Tx, s model.AdminSession, event string, newSessionHash ...string) error {
	if len(newSessionHash) > 1 {
		return ErrAdminConflict
	}
	if _, err := tx.Exec(ctx, `DELETE FROM admin_sessions WHERE account_id=$1::uuid`, s.Account.ID); err != nil {
		return err
	}
	if len(newSessionHash) == 1 {
		if _, err := tx.Exec(ctx, `INSERT INTO admin_sessions(account_id,token_hash,expires_at) VALUES($1::uuid,$2,now()+interval '8 hours')`, s.Account.ID, newSessionHash[0]); err != nil {
			return err
		}
		if err := adminAudit(ctx, tx, "admin_session.created", s.Account.ID, s.Account.Role); err != nil {
			return err
		}
	}
	return adminAudit(ctx, tx, event, s.Account.ID, s.Account.Role)
}

func (p *Postgres) DisableOwnAdminMFA(ctx context.Context, verifiedHash, code, recovery, master string) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	s, enabled, err := lockOwnAdminMFA(ctx, tx, verifiedHash)
	if err != nil {
		return err
	}
	if !enabled {
		return ErrAdminConflict
	}
	if err = consumeAdminMFA(ctx, tx, s.Account, code, recovery, master); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE admin_accounts SET mfa_enabled=false,password_hash=substring(password_hash FROM 5),security_version=security_version+1,updated_at=now() WHERE id=$1::uuid`, s.Account.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM admin_mfa WHERE account_id=$1::uuid`, s.Account.ID); err != nil {
		return err
	}
	if err = revokeMFAChange(ctx, tx, s, "admin_mfa.disabled"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) RotateOwnAdminRecoveryCodes(ctx context.Context, verifiedHash, code, recovery, master string, newSessionHash ...string) ([]string, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	s, enabled, err := lockOwnAdminMFA(ctx, tx, verifiedHash)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, ErrAdminConflict
	}
	if err = consumeAdminMFA(ctx, tx, s.Account, code, recovery, master); err != nil {
		return nil, err
	}
	codes, hashes, err := security.NewRecoveryCodes(s.Account.ID)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE admin_mfa SET recovery_hashes=$2,updated_at=now() WHERE account_id=$1::uuid`, s.Account.ID, hashes); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE admin_accounts SET security_version=security_version+1,updated_at=now() WHERE id=$1::uuid`, s.Account.ID); err != nil {
		return nil, err
	}
	if err = revokeMFAChange(ctx, tx, s, "admin_mfa.recovery_rotated", newSessionHash...); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return codes, nil
}
