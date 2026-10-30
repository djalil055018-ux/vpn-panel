package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/model"
)

type tenantPrincipalKey struct{}

func WithTenantPrincipal(ctx context.Context, token model.TenantAPIToken) context.Context {
	return context.WithValue(ctx, tenantPrincipalKey{}, token)
}
func TenantPrincipal(ctx context.Context) (model.TenantAPIToken, bool) {
	value, ok := ctx.Value(tenantPrincipalKey{}).(model.TenantAPIToken)
	return value, ok
}
func tenantScopeAllowed(ctx context.Context, tenant string) bool {
	value, ok := TenantPrincipal(ctx)
	return !ok || value.TenantID == tenant
}
func accessActor(ctx context.Context) (string, string) {
	if session, ok := AdminPrincipal(ctx); ok {
		return "admin_account", session.Account.ID
	}
	if token, ok := TenantPrincipal(ctx); ok {
		return "tenant_api_token", token.ID
	}
	return "admin", "control-plane"
}

const tenantTokenColumns = `id::text,tenant_id::text,name,role,created_at,expires_at,revoked_at,last_used_at`

var ErrTenantTokenLimit = errors.New("active tenant token limit reached")

func scanTenantToken(row pgx.Row) (model.TenantAPIToken, error) {
	var token model.TenantAPIToken
	err := row.Scan(&token.ID, &token.TenantID, &token.Name, &token.Role, &token.CreatedAt, &token.ExpiresAt, &token.RevokedAt, &token.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return token, err
}
func (p *Postgres) CreateTenantAPIToken(ctx context.Context, tenant, name, role, hash string, expires time.Time) (model.TenantAPIToken, error) {
	var out model.TenantAPIToken
	if _, scoped := TenantPrincipal(ctx); scoped {
		return out, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var id string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM tenants WHERE id=$1::uuid FOR UPDATE`, tenant).Scan(&id); errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	} else if err != nil {
		return out, err
	}
	if role == "reseller" {
		var nested bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM reseller_children WHERE child_tenant_id=$1::uuid)`, tenant).Scan(&nested); err != nil {
			return out, err
		}
		if nested {
			return out, ErrResellerHierarchy
		}
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM tenant_api_tokens WHERE tenant_id=$1::uuid AND revoked_at IS NULL AND expires_at>now()`, tenant).Scan(&count); err != nil {
		return out, err
	}
	if count >= 20 {
		return out, ErrTenantTokenLimit
	}
	out, err = scanTenantToken(tx.QueryRow(ctx, `INSERT INTO tenant_api_tokens(tenant_id,name,role,token_hash,expires_at) VALUES($1::uuid,$2,$3,$4,$5) RETURNING `+tenantTokenColumns, tenant, name, role, hash, expires))
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'tenant_api_token.created','admin','control-plane',jsonb_build_object('token_id',$2::text,'role',$3::text))`, tenant, out.ID, role)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (p *Postgres) ListTenantAPITokens(ctx context.Context, tenant string) ([]model.TenantAPIToken, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+tenantTokenColumns+` FROM tenant_api_tokens WHERE tenant_id=$1::uuid ORDER BY created_at DESC,id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.TenantAPIToken{}
	for rows.Next() {
		token, err := scanTenantToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, token)
	}
	return out, rows.Err()
}
func (p *Postgres) RevokeTenantAPIToken(ctx context.Context, id string) (model.TenantAPIToken, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return model.TenantAPIToken{}, ErrNotFound
	}
	var out model.TenantAPIToken
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	out, err = scanTenantToken(tx.QueryRow(ctx, `SELECT `+tenantTokenColumns+` FROM tenant_api_tokens WHERE id=$1::uuid FOR UPDATE`, id))
	if err != nil {
		return out, err
	}
	if out.RevokedAt == nil {
		out, err = scanTenantToken(tx.QueryRow(ctx, `UPDATE tenant_api_tokens SET revoked_at=now() WHERE id=$1::uuid RETURNING `+tenantTokenColumns, id))
		if err != nil {
			return out, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'tenant_api_token.revoked','admin','control-plane',jsonb_build_object('token_id',$2::text))`, out.TenantID, id)
		if err != nil {
			return out, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE tenant_api_tokens SET revoked_at=coalesce(revoked_at,now()) WHERE issued_by_token_id=$1::uuid`, id); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (p *Postgres) AuthenticateTenantAPIToken(ctx context.Context, hash string) (model.TenantAPIToken, error) {
	token, err := scanTenantToken(p.Pool.QueryRow(ctx, `SELECT `+tenantTokenColumns+` FROM tenant_api_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at>now() AND (issued_by_token_id IS NULL OR EXISTS(SELECT 1 FROM tenant_api_tokens issuer JOIN reseller_children rc ON rc.parent_tenant_id=issuer.tenant_id AND rc.child_tenant_id=tenant_api_tokens.tenant_id WHERE issuer.id=tenant_api_tokens.issued_by_token_id AND issuer.role='reseller' AND issuer.issued_by_token_id IS NULL AND issuer.revoked_at IS NULL AND issuer.expires_at>now()))`, hash))
	if err != nil {
		return token, err
	}
	// Metadata is advisory; authentication is always checked against the current row.
	_, err = p.Pool.Exec(ctx, `UPDATE tenant_api_tokens SET last_used_at=now() WHERE id=$1::uuid AND (last_used_at IS NULL OR last_used_at<now()-interval '5 minutes')`, token.ID)
	return token, err
}

// Resource kinds are a closed allowlist, never table names supplied by a caller.
func (p *Postgres) TenantOwnsResource(ctx context.Context, tenant, kind, id string) (bool, error) {
	query := ""
	switch kind {
	case "plan":
		query = `SELECT EXISTS(SELECT 1 FROM vpn_access_plans WHERE id=$1::uuid AND tenant_id=$2::uuid)`
	case "client":
		query = `SELECT EXISTS(SELECT 1 FROM vpn_clients WHERE id=$1::uuid AND tenant_id=$2::uuid)`
	case "service":
		query = `SELECT EXISTS(SELECT 1 FROM vpn_services WHERE id=$1::uuid AND tenant_id=$2::uuid)`
	case "invoice":
		query = `SELECT EXISTS(SELECT 1 FROM billing_invoices WHERE id=$1::uuid AND tenant_id=$2::uuid)`
	default:
		return false, ErrNotFound
	}
	var owns bool
	err := p.Pool.QueryRow(ctx, query, id, tenant).Scan(&owns)
	return owns, err
}
