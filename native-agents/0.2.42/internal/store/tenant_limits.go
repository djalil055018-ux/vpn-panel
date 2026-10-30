package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

var ErrTenantQuota = errors.New("tenant resource limit reached or below current usage")

const tenantLimitsQuery = `SELECT t.id::text,coalesce(l.max_clients,0),coalesce(l.max_plans,0),(SELECT count(*) FROM vpn_clients c WHERE c.tenant_id=t.id),(SELECT count(*) FROM vpn_access_plans ap WHERE ap.tenant_id=t.id) FROM tenants t LEFT JOIN tenant_resource_limits l ON l.tenant_id=t.id WHERE t.id=$1::uuid`

func scanTenantLimits(row pgx.Row) (model.TenantResourceLimits, error) {
	var v model.TenantResourceLimits
	err := row.Scan(&v.TenantID, &v.MaxClients, &v.MaxPlans, &v.Clients, &v.Plans)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return v, err
}
func lockTenantResource(ctx context.Context, tx pgx.Tx, tenant string) error {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM tenants WHERE id=$1::uuid FOR UPDATE`, tenant).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
func checkTenantQuota(ctx context.Context, tx pgx.Tx, tenant, kind string) error {
	if err := lockTenantResource(ctx, tx, tenant); err != nil {
		return err
	}
	v, err := scanTenantLimits(tx.QueryRow(ctx, tenantLimitsQuery, tenant))
	if err != nil {
		return err
	}
	switch kind {
	case "client":
		if v.MaxClients > 0 && v.Clients >= v.MaxClients {
			return ErrTenantQuota
		}
	case "plan":
		if v.MaxPlans > 0 && v.Plans >= v.MaxPlans {
			return ErrTenantQuota
		}
	default:
		return ErrNotFound
	}
	return nil
}
func (p *Postgres) TenantResourceLimits(ctx context.Context, tenant string) (model.TenantResourceLimits, error) {
	if !tenantScopeAllowed(ctx, tenant) {
		return model.TenantResourceLimits{}, ErrNotFound
	}
	return scanTenantLimits(p.Pool.QueryRow(ctx, tenantLimitsQuery, tenant))
}
func (p *Postgres) SetTenantResourceLimits(ctx context.Context, tenant string, clients, plans int) (model.TenantResourceLimits, error) {
	out := model.TenantResourceLimits{}
	if _, ok := TenantPrincipal(ctx); ok {
		return out, ErrNotFound
	}
	if clients < 0 || clients > 100000 || plans < 0 || plans > 10000 {
		return out, ErrTenantQuota
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return out, err
	}
	out, err = scanTenantLimits(tx.QueryRow(ctx, tenantLimitsQuery, tenant))
	if err != nil {
		return out, err
	}
	if clients > 0 && clients < out.Clients || plans > 0 && plans < out.Plans {
		return out, ErrTenantQuota
	}
	if clients == out.MaxClients && plans == out.MaxPlans {
		return out, tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, `INSERT INTO tenant_resource_limits(tenant_id,max_clients,max_plans) VALUES($1::uuid,$2,$3) ON CONFLICT(tenant_id) DO UPDATE SET max_clients=EXCLUDED.max_clients,max_plans=EXCLUDED.max_plans,updated_at=now()`, tenant, clients, plans)
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'tenant.limits_updated','admin','control-plane',jsonb_build_object('max_clients',$2::integer,'max_plans',$3::integer))`, tenant, clients, plans)
	if err != nil {
		return out, err
	}
	out.MaxClients = clients
	out.MaxPlans = plans
	return out, tx.Commit(ctx)
}
