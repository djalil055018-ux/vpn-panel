package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

var ErrAutoProfileSettings = errors.New("invalid automatic profile settings")

type autoProfileReader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readAutoProfileSettings(ctx context.Context, reader autoProfileReader, tenant string) (model.AutoProfileSettings, error) {
	var settings model.AutoProfileSettings
	if !tenantScopeAllowed(ctx, tenant) {
		return settings, ErrNotFound
	}
	err := reader.QueryRow(ctx, `SELECT t.id::text,coalesce(a.enabled,false),coalesce(a.name,'Авто'),coalesce(a.russia_direct,true)
 FROM tenants t LEFT JOIN tenant_auto_profiles a ON a.tenant_id=t.id WHERE t.id=$1::uuid`, tenant).Scan(&settings.TenantID, &settings.Enabled, &settings.Name, &settings.RussiaDirect)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return settings, err
}

func (p *Postgres) GetAutoProfileSettings(ctx context.Context, tenant string) (model.AutoProfileSettings, error) {
	return readAutoProfileSettings(ctx, p.Pool, tenant)
}

func (p *Postgres) SetAutoProfileSettings(ctx context.Context, tenant string, settings model.AutoProfileSettings) (model.AutoProfileSettings, error) {
	if !tenantScopeAllowed(ctx, tenant) {
		return model.AutoProfileSettings{}, ErrNotFound
	}
	if !model.ValidAutoProfileName(settings.Name) {
		return model.AutoProfileSettings{}, ErrAutoProfileSettings
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.AutoProfileSettings{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	err = tx.QueryRow(ctx, `INSERT INTO tenant_auto_profiles(tenant_id,enabled,name,russia_direct)
 SELECT id,$2,$3,$4 FROM tenants WHERE id=$1::uuid
 ON CONFLICT(tenant_id) DO UPDATE SET enabled=excluded.enabled,name=excluded.name,russia_direct=excluded.russia_direct,updated_at=now()
 RETURNING tenant_id::text`, tenant, settings.Enabled, settings.Name, settings.RussiaDirect).Scan(&settings.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.AutoProfileSettings{}, ErrNotFound
	}
	if err != nil {
		return model.AutoProfileSettings{}, err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload)
 VALUES($1::uuid,'tenant.auto_profile_updated',$2,$3,jsonb_build_object('enabled',$4::boolean,'russia_direct',$5::boolean))`, tenant, actorType, actorID, settings.Enabled, settings.RussiaDirect)
	if err != nil {
		return model.AutoProfileSettings{}, err
	}
	return settings, tx.Commit(ctx)
}
