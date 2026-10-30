package store

import (
	"context"
	"vpn-platform/internal/model"
)

// Session identifiers are safe revocation handles, never bearer credentials.
func (p *Postgres) ListOwnAdminSessions(ctx context.Context) ([]model.AdminSessionInfo, error) {
	principal, ok := AdminPrincipal(ctx)
	if !ok {
		return nil, ErrAdminPermission
	}
	rows, err := p.Pool.Query(ctx, `SELECT id::text,created_at,expires_at FROM admin_sessions WHERE account_id=$1::uuid AND expires_at>now() ORDER BY created_at DESC,id DESC LIMIT 20`, principal.Account.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AdminSessionInfo{}
	for rows.Next() {
		var item model.AdminSessionInfo
		if err = rows.Scan(&item.ID, &item.CreatedAt, &item.ExpiresAt); err != nil {
			return nil, err
		}
		item.Current = item.ID == principal.ID
		out = append(out, item)
	}
	return out, rows.Err()
}

func (p *Postgres) RevokeOwnAdminSessions(ctx context.Context, id string) (int64, error) {
	principal, ok := AdminPrincipal(ctx)
	if !ok {
		return 0, ErrAdminPermission
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Serialize with login/password changes on this account. Another account's
	// identifier never broadens the account scope.
	var lockedID string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM admin_accounts WHERE id=$1::uuid FOR UPDATE`, principal.Account.ID).Scan(&lockedID); err != nil {
		return 0, err
	}
	var count int64
	if id == "" {
		if _, err = tx.Exec(ctx, `UPDATE admin_accounts SET security_version=security_version+1,updated_at=now() WHERE id=$1::uuid`, principal.Account.ID); err != nil {
			return 0, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM admin_sessions WHERE account_id=$1::uuid`, principal.Account.ID)
		if err != nil {
			return 0, err
		}
		count = tag.RowsAffected()
	} else {
		tag, err := tx.Exec(ctx, `DELETE FROM admin_sessions WHERE account_id=$1::uuid AND id=$2::uuid`, principal.Account.ID, id)
		if err != nil {
			return 0, err
		}
		count = tag.RowsAffected()
		if count == 0 {
			return 0, ErrNotFound
		}
	}
	event := "admin_session.revoked"
	if id == "" {
		event = "admin_session.all_revoked"
	}
	if err = adminAudit(ctx, tx, event, principal.Account.ID, principal.Account.Role); err != nil {
		return 0, err
	}
	return count, tx.Commit(ctx)
}
