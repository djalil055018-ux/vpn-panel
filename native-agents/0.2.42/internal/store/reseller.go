package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/model"
)

var ErrResellerLimit = errors.New("maximum 20 child tenants")
var ErrResellerHierarchy = errors.New("reseller requires a top-level tenant")

func resellerPrincipal(ctx context.Context) (model.TenantAPIToken, error) {
	t, ok := TenantPrincipal(ctx)
	if !ok || t.Role != "reseller" {
		return t, ErrNotFound
	}
	return t, nil
}
func lockResellerCredential(ctx context.Context, tx pgx.Tx, t model.TenantAPIToken) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM tenant_api_tokens WHERE id=$1::uuid AND tenant_id=$2::uuid AND role='reseller' AND issued_by_token_id IS NULL AND revoked_at IS NULL AND expires_at>now() FOR SHARE`, t.ID, t.TenantID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
func (p *Postgres) ListResellerChildren(ctx context.Context, parent string) ([]model.ResellerChild, error) {
	if t, scoped := TenantPrincipal(ctx); scoped && (t.Role != "reseller" || t.TenantID != parent) {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT t.id::text,t.name,rc.created_at,(SELECT count(*) FROM vpn_clients c WHERE c.tenant_id=t.id),(SELECT count(*) FROM vpn_services s WHERE s.tenant_id=t.id AND s.enabled) FROM reseller_children rc JOIN tenants t ON t.id=rc.child_tenant_id WHERE rc.parent_tenant_id=$1::uuid ORDER BY rc.created_at DESC,t.id`, parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.ResellerChild{}
	for rows.Next() {
		var child model.ResellerChild
		if err = rows.Scan(&child.ID, &child.Name, &child.CreatedAt, &child.ClientCount, &child.ServiceCount); err != nil {
			return nil, err
		}
		out = append(out, child)
	}
	return out, rows.Err()
}
func (p *Postgres) CreateResellerChild(ctx context.Context, name string) (model.ResellerChild, error) {
	child := model.ResellerChild{}
	t, err := resellerPrincipal(ctx)
	if err != nil {
		return child, err
	}
	if name == "" || len(name) > 100 {
		return child, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return child, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockResellerCredential(ctx, tx, t); err != nil {
		return child, err
	}
	var id string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM tenants WHERE id=$1::uuid FOR UPDATE`, t.TenantID).Scan(&id); err != nil {
		return child, err
	}
	var nested bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM reseller_children WHERE child_tenant_id=$1::uuid)`, t.TenantID).Scan(&nested); err != nil {
		return child, err
	}
	if nested {
		return child, ErrResellerHierarchy
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM reseller_children WHERE parent_tenant_id=$1::uuid`, t.TenantID).Scan(&count); err != nil {
		return child, err
	}
	if count >= 20 {
		return child, ErrResellerLimit
	}
	if err = tx.QueryRow(ctx, `INSERT INTO tenants(name) VALUES($1) RETURNING id::text,name,created_at`, name).Scan(&child.ID, &child.Name, &child.CreatedAt); err != nil {
		return child, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO reseller_children(child_tenant_id,parent_tenant_id) VALUES($1::uuid,$2::uuid)`, child.ID, t.TenantID); err != nil {
		return child, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'reseller.child_created','tenant_api_token',$2,jsonb_build_object('child_tenant_id',$3::text))`, t.TenantID, t.ID, child.ID)
	if err != nil {
		return child, err
	}
	return child, tx.Commit(ctx)
}
func (p *Postgres) ResellerOwnsChild(ctx context.Context, child string) (bool, error) {
	t, err := resellerPrincipal(ctx)
	if err != nil {
		return false, err
	}
	var owns bool
	err = p.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM reseller_children WHERE child_tenant_id=$1::uuid AND parent_tenant_id=$2::uuid)`, child, t.TenantID).Scan(&owns)
	return owns, err
}
func (p *Postgres) ListResellerChildTokens(ctx context.Context, child string) ([]model.TenantAPIToken, error) {
	t, err := resellerPrincipal(ctx)
	if err != nil {
		return nil, err
	}
	owns, err := p.ResellerOwnsChild(ctx, child)
	if err != nil {
		return nil, err
	}
	if !owns {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+tenantTokenColumns+` FROM tenant_api_tokens WHERE tenant_id=$1::uuid AND issued_by_token_id IN (SELECT id FROM tenant_api_tokens WHERE tenant_id=$2::uuid) ORDER BY created_at DESC,id`, child, t.TenantID)
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
func (p *Postgres) CreateResellerChildToken(ctx context.Context, child, name, role, hash string, expires time.Time) (model.TenantAPIToken, error) {
	out := model.TenantAPIToken{}
	t, err := resellerPrincipal(ctx)
	if err != nil {
		return out, err
	}
	if (role != "viewer" && role != "operator") || expires.After(t.ExpiresAt) || !expires.After(time.Now()) || name == "" || len(name) > 100 {
		return out, ErrResellerHierarchy
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockResellerCredential(ctx, tx, t); err != nil {
		return out, err
	}
	var id string
	err = tx.QueryRow(ctx, `SELECT t.id::text FROM tenants t JOIN reseller_children rc ON rc.child_tenant_id=t.id WHERE t.id=$1::uuid AND rc.parent_tenant_id=$2::uuid FOR UPDATE OF t`, child, t.TenantID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM tenant_api_tokens WHERE tenant_id=$1::uuid AND revoked_at IS NULL AND expires_at>now()`, child).Scan(&count); err != nil {
		return out, err
	}
	if count >= 20 {
		return out, ErrTenantTokenLimit
	}
	out, err = scanTenantToken(tx.QueryRow(ctx, `INSERT INTO tenant_api_tokens(tenant_id,name,role,token_hash,expires_at,issued_by_token_id) VALUES($1::uuid,$2,$3,$4,$5,$6::uuid) RETURNING `+tenantTokenColumns, child, name, role, hash, expires, t.ID))
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'reseller.child_key_created','tenant_api_token',$2,jsonb_build_object('token_id',$3::text,'role',$4::text))`, child, t.ID, out.ID, role)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (p *Postgres) RevokeResellerChildToken(ctx context.Context, child, id string) (model.TenantAPIToken, error) {
	out := model.TenantAPIToken{}
	t, err := resellerPrincipal(ctx)
	if err != nil {
		return out, err
	}
	owns, err := p.ResellerOwnsChild(ctx, child)
	if err != nil {
		return out, err
	}
	if !owns {
		return out, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockResellerCredential(ctx, tx, t); err != nil {
		return out, err
	}
	out, err = scanTenantToken(tx.QueryRow(ctx, `SELECT `+tenantTokenColumns+` FROM tenant_api_tokens WHERE id=$1::uuid AND tenant_id=$2::uuid AND issued_by_token_id IN(SELECT id FROM tenant_api_tokens WHERE tenant_id=$3::uuid) FOR UPDATE`, id, child, t.TenantID))
	if err != nil {
		return out, err
	}
	if out.RevokedAt != nil {
		return out, tx.Commit(ctx)
	}
	out, err = scanTenantToken(tx.QueryRow(ctx, `UPDATE tenant_api_tokens SET revoked_at=now() WHERE id=$1::uuid RETURNING `+tenantTokenColumns, id))
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'reseller.child_key_revoked','tenant_api_token',$2,jsonb_build_object('token_id',$3::text))`, child, t.ID, id)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
