package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

func (p *Postgres) GetTenantBranding(ctx context.Context, tenant string) (model.TenantBranding, error) {
	b := model.TenantBranding{}
	if !tenantScopeAllowed(ctx, tenant) {
		return b, ErrNotFound
	}
	err := p.Pool.QueryRow(ctx, `SELECT t.id::text,coalesce(b.display_name,'PAUK'),coalesce(b.tagline,''),coalesce(b.support_label,''),coalesce(b.support_url,''),coalesce(b.accent,'blue') FROM tenants t LEFT JOIN tenant_branding b ON b.tenant_id=t.id WHERE t.id=$1::uuid`, tenant).Scan(&b.TenantID, &b.DisplayName, &b.Tagline, &b.SupportLabel, &b.SupportURL, &b.Accent)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return b, err
}
func (p *Postgres) SetTenantBranding(ctx context.Context, tenant string, b model.TenantBranding) (model.TenantBranding, error) {
	if !tenantScopeAllowed(ctx, tenant) {
		return b, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return b, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	err = tx.QueryRow(ctx, `INSERT INTO tenant_branding(tenant_id,display_name,tagline,support_label,support_url,accent) SELECT id,$2,$3,$4,$5,$6 FROM tenants WHERE id=$1::uuid ON CONFLICT(tenant_id) DO UPDATE SET display_name=excluded.display_name,tagline=excluded.tagline,support_label=excluded.support_label,support_url=excluded.support_url,accent=excluded.accent,updated_at=now() RETURNING tenant_id::text`, tenant, b.DisplayName, b.Tagline, b.SupportLabel, b.SupportURL, b.Accent).Scan(&b.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, ErrNotFound
	}
	if err != nil {
		return b, err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'tenant.branding_updated',$2,$3,jsonb_build_object('accent',$4::text))`, tenant, actorType, actorID, b.Accent)
	if err != nil {
		return b, err
	}
	return b, tx.Commit(ctx)
}
