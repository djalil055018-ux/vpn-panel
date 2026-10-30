package store

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

var ErrAdminPermission = errors.New("administrator permission required")
var ErrAdminConflict = errors.New("administrator account conflict")
var ErrLastOwner = errors.New("at least one enabled owner is required")
var adminUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type adminPrincipalKey struct{}

func WithAdminPrincipal(ctx context.Context, session model.AdminSession) context.Context {
	return context.WithValue(ctx, adminPrincipalKey{}, session)
}
func AdminPrincipal(ctx context.Context) (model.AdminSession, bool) {
	value, ok := ctx.Value(adminPrincipalKey{}).(model.AdminSession)
	return value, ok
}
func adminOwnerAllowed(ctx context.Context) bool {
	if _, tenant := TenantPrincipal(ctx); tenant {
		return false
	}
	value, ok := AdminPrincipal(ctx)
	return !ok || value.Account.Role == "owner"
}
func ValidAdminUsername(value string) bool { return adminUsername.MatchString(value) }
func ValidAdminRole(value string) bool {
	return value == "owner" || value == "admin" || value == "monitor"
}

const adminAccountColumns = `id::text,username,role,enabled,security_version,created_at,updated_at,last_login_at`

func scanAdminAccount(row interface{ Scan(...any) error }) (model.AdminAccount, error) {
	var a model.AdminAccount
	err := row.Scan(&a.ID, &a.Username, &a.Role, &a.Enabled, &a.SecurityVersion, &a.CreatedAt, &a.UpdatedAt, &a.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return a, err
}
func lockAdminAccounts(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103506,1)`)
	return err
}
func adminAudit(ctx context.Context, tx pgx.Tx, event, id, role string) error {
	kind, actor := accessActor(ctx)
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(event_type,actor_type,actor_id,payload) VALUES($1,$2,$3,jsonb_build_object('admin_account_id',$4::text,'role',$5::text))`, event, kind, actor, id, role)
	return err
}
func adminConflict(err error) error {
	var p *pgconn.PgError
	if errors.As(err, &p) && p.Code == "23505" {
		return ErrAdminConflict
	}
	return err
}

// Bootstrap is root-token-only at the HTTP boundary. It never resets or adds an
// owner after any account exists, even if the old environment later changes.
func (p *Postgres) BootstrapAdminOwner(ctx context.Context, username, hash string) (*model.AdminAccount, error) {
	if _, ok := AdminPrincipal(ctx); ok {
		return nil, ErrAdminPermission
	}
	if _, ok := TenantPrincipal(ctx); ok {
		return nil, ErrAdminPermission
	}
	if !ValidAdminUsername(username) || !security.ValidPasswordHash(hash) {
		return nil, ErrAdminConflict
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAdminAccounts(ctx, tx); err != nil {
		return nil, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM admin_accounts`).Scan(&count); err != nil {
		return nil, err
	}
	if count == 0 {
		a, err := scanAdminAccount(tx.QueryRow(ctx, `INSERT INTO admin_accounts(username,password_hash,role) VALUES($1,$2,'owner') RETURNING `+adminAccountColumns, username, hash))
		if err != nil {
			return nil, err
		}
		if err = adminAudit(ctx, tx, "admin_account.bootstrapped", a.ID, a.Role); err != nil {
			return nil, err
		}
		return &a, tx.Commit(ctx)
	}
	a, err := scanAdminAccount(tx.QueryRow(ctx, `SELECT `+adminAccountColumns+` FROM admin_accounts WHERE lower(username)=lower($1)`, username))
	if errors.Is(err, ErrNotFound) {
		return nil, tx.Commit(ctx)
	}
	if err != nil {
		return nil, err
	}
	return &a, tx.Commit(ctx)
}

func (p *Postgres) ListAdminAccounts(ctx context.Context) ([]model.AdminAccount, error) {
	if !adminOwnerAllowed(ctx) {
		return nil, ErrAdminPermission
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+adminAccountColumns+` FROM admin_accounts ORDER BY lower(username) LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AdminAccount{}
	for rows.Next() {
		a, err := scanAdminAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) CreateAdminAccount(ctx context.Context, username, role, hash string) (model.AdminAccount, error) {
	if !adminOwnerAllowed(ctx) {
		return model.AdminAccount{}, ErrAdminPermission
	}
	if !ValidAdminUsername(username) || !ValidAdminRole(role) || !security.ValidPasswordHash(hash) {
		return model.AdminAccount{}, ErrAdminConflict
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.AdminAccount{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAdminAccounts(ctx, tx); err != nil {
		return model.AdminAccount{}, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM admin_accounts`).Scan(&count); err != nil {
		return model.AdminAccount{}, err
	}
	if count >= 1000 {
		return model.AdminAccount{}, ErrAdminConflict
	}
	if count == 0 && role != "owner" {
		return model.AdminAccount{}, ErrLastOwner
	}
	a, err := scanAdminAccount(tx.QueryRow(ctx, `INSERT INTO admin_accounts(username,role,password_hash) VALUES($1,$2,$3) RETURNING `+adminAccountColumns, username, role, hash))
	if err != nil {
		return a, adminConflict(err)
	}
	if err = adminAudit(ctx, tx, "admin_account.created", a.ID, a.Role); err != nil {
		return a, err
	}
	return a, tx.Commit(ctx)
}

func (p *Postgres) UpdateAdminAccount(ctx context.Context, id string, role *string, enabled *bool, hash *string) (model.AdminAccount, error) {
	if !adminOwnerAllowed(ctx) {
		return model.AdminAccount{}, ErrAdminPermission
	}
	if role != nil && !ValidAdminRole(*role) || hash != nil && !security.ValidPasswordHash(*hash) {
		return model.AdminAccount{}, ErrAdminConflict
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.AdminAccount{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockAdminAccounts(ctx, tx); err != nil {
		return model.AdminAccount{}, err
	}
	a, err := scanAdminAccount(tx.QueryRow(ctx, `SELECT `+adminAccountColumns+` FROM admin_accounts WHERE id=$1::uuid FOR UPDATE`, id))
	if err != nil {
		return a, err
	}
	newRole, newEnabled := a.Role, a.Enabled
	if role != nil {
		newRole = *role
	}
	if enabled != nil {
		newEnabled = *enabled
	}
	if a.Role == "owner" && a.Enabled && (newRole != "owner" || !newEnabled) {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM admin_accounts WHERE role='owner' AND enabled`).Scan(&count); err != nil {
			return a, err
		}
		if count <= 1 {
			return a, ErrLastOwner
		}
	}
	if newRole == a.Role && newEnabled == a.Enabled && hash == nil {
		return a, tx.Commit(ctx)
	}
	a, err = scanAdminAccount(tx.QueryRow(ctx, `UPDATE admin_accounts SET role=$2,enabled=$3,password_hash=CASE WHEN $4::text IS NULL THEN password_hash WHEN mfa_enabled THEN 'mfa$'||$4::text ELSE $4::text END,security_version=security_version+1,updated_at=now() WHERE id=$1::uuid RETURNING `+adminAccountColumns, id, newRole, newEnabled, hash))
	if err != nil {
		return a, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM admin_sessions WHERE account_id=$1::uuid`, id); err != nil {
		return a, err
	}
	if err = adminAudit(ctx, tx, "admin_account.updated", id, a.Role); err != nil {
		return a, err
	}
	return a, tx.Commit(ctx)
}

func (p *Postgres) AdminLoginRecord(ctx context.Context, username string) (model.AdminAccount, string, error) {
	var id, hash string
	err := p.Pool.QueryRow(ctx, `SELECT id::text,password_hash FROM admin_accounts WHERE lower(username)=lower($1) AND enabled`, strings.TrimSpace(username)).Scan(&id, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.AdminAccount{}, "", ErrNotFound
	}
	if err != nil {
		return model.AdminAccount{}, "", err
	}
	a, err := scanAdminAccount(p.Pool.QueryRow(ctx, `SELECT `+adminAccountColumns+` FROM admin_accounts WHERE id=$1::uuid`, id))
	return a, hash, err
}

func (p *Postgres) CreateAdminSession(ctx context.Context, id, verifiedHash, newHash, tokenHash string) (model.AdminSession, error) {
	return p.CreateAdminSessionWithMFA(ctx, id, verifiedHash, newHash, tokenHash, "", "", "")
}

func (p *Postgres) CreateAdminSessionWithMFA(ctx context.Context, id, verifiedHash, newHash, tokenHash, code, recovery, master string) (model.AdminSession, error) {
	var out model.AdminSession
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var current string
	var mfaEnabled bool
	if err = tx.QueryRow(ctx, `SELECT password_hash,mfa_enabled FROM admin_accounts WHERE id=$1::uuid AND enabled FOR UPDATE`, id).Scan(&current, &mfaEnabled); errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	} else if err != nil {
		return out, err
	}
	if !security.EqualSecret(current, verifiedHash) {
		return out, ErrAdminConflict
	}
	if mfaEnabled {
		out.Account, err = scanAdminAccount(tx.QueryRow(ctx, `SELECT `+adminAccountColumns+` FROM admin_accounts WHERE id=$1::uuid`, id))
		if err != nil {
			return out, err
		}
		if err = consumeAdminMFA(ctx, tx, out.Account, code, recovery, master); err != nil {
			return out, err
		}
	}
	if newHash != "" && !security.ValidPasswordHash(newHash) {
		return out, ErrAdminConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE admin_accounts SET password_hash=CASE WHEN $2::text='' THEN password_hash WHEN mfa_enabled THEN 'mfa$'||$2::text ELSE $2::text END,last_login_at=now() WHERE id=$1::uuid`, id, newHash); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM admin_sessions WHERE expires_at<now()-interval '7 days' OR id IN(SELECT id FROM admin_sessions WHERE account_id=$1::uuid ORDER BY created_at DESC OFFSET 19)`, id); err != nil {
		return out, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO admin_sessions(account_id,token_hash,expires_at) VALUES($1::uuid,$2,now()+interval '8 hours') RETURNING id::text,created_at,expires_at`, id, tokenHash).Scan(&out.ID, &out.CreatedAt, &out.ExpiresAt)
	if err != nil {
		return out, err
	}
	out.Account, err = scanAdminAccount(tx.QueryRow(ctx, `SELECT `+adminAccountColumns+` FROM admin_accounts WHERE id=$1::uuid`, id))
	if err != nil {
		return out, err
	}
	if err = adminAudit(WithAdminPrincipal(ctx, out), tx, "admin_session.created", id, out.Account.Role); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func (p *Postgres) AuthenticateAdminSession(ctx context.Context, hash string) (model.AdminSession, error) {
	var s model.AdminSession
	err := p.Pool.QueryRow(ctx, `SELECT s.id::text,s.created_at,s.expires_at,a.id::text,a.username,a.role,a.enabled,a.security_version,a.created_at,a.updated_at,a.last_login_at FROM admin_sessions s JOIN admin_accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.expires_at>now() AND a.enabled`, hash).Scan(&s.ID, &s.CreatedAt, &s.ExpiresAt, &s.Account.ID, &s.Account.Username, &s.Account.Role, &s.Account.Enabled, &s.Account.SecurityVersion, &s.Account.CreatedAt, &s.Account.UpdatedAt, &s.Account.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, ErrNotFound
	}
	if err != nil {
		return s, err
	}
	return s, nil
}

func (p *Postgres) RevokeAdminSession(ctx context.Context, id string) error {
	s, ok := AdminPrincipal(ctx)
	if !ok || s.ID != id {
		return ErrAdminPermission
	}
	_, err := p.Pool.Exec(ctx, `DELETE FROM admin_sessions WHERE id=$1::uuid AND account_id=$2::uuid`, id, s.Account.ID)
	return err
}

func (p *Postgres) ChangeOwnAdminPassword(ctx context.Context, verifiedHash, newHash string) error {
	s, ok := AdminPrincipal(ctx)
	if !ok || !security.ValidPasswordHash(newHash) {
		return ErrAdminPermission
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var current string
	if err = tx.QueryRow(ctx, `SELECT password_hash FROM admin_accounts WHERE id=$1::uuid AND enabled FOR UPDATE`, s.Account.ID).Scan(&current); err != nil {
		return err
	}
	if !security.EqualSecret(current, verifiedHash) {
		return ErrAdminConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE admin_accounts SET password_hash=CASE WHEN mfa_enabled THEN 'mfa$'||$2::text ELSE $2::text END,security_version=security_version+1,updated_at=now() WHERE id=$1::uuid`, s.Account.ID, newHash); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM admin_sessions WHERE account_id=$1::uuid`, s.Account.ID); err != nil {
		return err
	}
	if err = adminAudit(ctx, tx, "admin_account.password_changed", s.Account.ID, s.Account.Role); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) RecordAdminMutationIntent(ctx context.Context, method, pattern string) error {
	_, err := p.BeginAdminMutation(ctx, method, pattern)
	return err
}

func (p *Postgres) BeginAdminMutation(ctx context.Context, method, pattern string) (string, error) {
	s, ok := AdminPrincipal(ctx)
	if !ok {
		return "", ErrNotFound
	}
	var id string
	err := p.Pool.QueryRow(ctx, `INSERT INTO audit_events(event_type,actor_type,actor_id,payload) VALUES('admin_request.started','admin_account',$1,jsonb_build_object('method',$2::text,'route',$3::text)) RETURNING id::text`, s.Account.ID, method, pattern).Scan(&id)
	return id, err
}

// CompleteAdminMutation appends a response receipt; it never rewrites the intent
// or records response bodies. An HTTP acceptance is not a VPN rollout receipt.
func (p *Postgres) CompleteAdminMutation(ctx context.Context, requestID string, status int, responded bool) error {
	s, ok := AdminPrincipal(ctx)
	if !ok {
		return ErrNotFound
	}
	outcome := "interrupted"
	var code any
	if responded {
		if status < 200 || status > 599 {
			return ErrAdminConflict
		}
		outcome, code = "responded", status
	}
	result, err := p.Pool.Exec(ctx, `INSERT INTO audit_events(event_type,actor_type,actor_id,payload)
 SELECT 'admin_request.completed','admin_account',actor_id,jsonb_build_object('request_id',id::text,'outcome',$3::text,'http_status',$4::int)
 FROM audit_events WHERE id=$1::uuid AND event_type='admin_request.started' AND actor_type='admin_account' AND actor_id=$2`, requestID, s.Account.ID, outcome, code)
	if err == nil && result.RowsAffected() != 1 {
		return ErrNotFound
	}
	return err
}
