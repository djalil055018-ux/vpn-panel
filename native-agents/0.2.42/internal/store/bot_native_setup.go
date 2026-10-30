package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/url"
	"strings"
)

type NativeBotSetup struct {
	TenantID         string `json:"tenant_id"`
	SubscriptionBase string `json:"subscription_base"`
	AccessPlanID     string `json:"access_plan_id"`
	SquadID          string `json:"squad_id"`
}

// Called with tenant resource/access locks already held. Native purchases and
// changes use the same cap as public subscription registration. Never silently
// evict a registered device when lowering a paid allowance.
func syncNativeBotDeviceLimitTx(ctx context.Context, tx pgx.Tx, tenant, client string, limit int) error {
	var native bool
	if err := tx.QueryRow(ctx, `SELECT profile_kind='native' FROM bot_profiles WHERE tenant_id=$1::uuid`, tenant).Scan(&native); err != nil {
		return err
	}
	if !native {
		return nil
	}
	if limit > 0 {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM bot_devices WHERE client_id=$1::uuid`, client).Scan(&count); err != nil {
			return err
		}
		if count > limit {
			return ErrBotBridgeConflict
		}
	}
	_, err := tx.Exec(ctx, `UPDATE vpn_clients SET registered_device_limit=$2,updated_at=now() WHERE id=$1::uuid AND tenant_id=$3::uuid`, client, limit, tenant)
	return err
}

func validNativeSubscriptionBase(base string) bool {
	u, err := url.Parse(base)
	return err == nil && len(base) <= 2048 && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" &&
		!u.ForceQuery && u.Path == "/sub/" && !strings.ContainsAny(base, "\r\n\x00")
}

// ConfigureNativeBot creates the bridge for a fresh tenant. It never fabricates
// imported inventory, adopts an imported profile, or creates customer accounts.
// Replay with the same configuration is safe; conflicting configuration fails.
func (p *Postgres) ConfigureNativeBot(ctx context.Context, tenant, base, plan string) (out NativeBotSetup, err error) {
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	if !botSquadUUID.MatchString(tenant) || !botSquadUUID.MatchString(plan) || !validNativeSubscriptionBase(base) {
		return out, ErrBotBridgeRequest
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	var name string
	err = tx.QueryRow(ctx, `SELECT p.name FROM vpn_access_plans p JOIN tenants t ON t.id=p.tenant_id WHERE p.id=$1::uuid AND p.tenant_id=$2::uuid AND p.enabled FOR SHARE OF p,t`, plan, tenant).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	var kind, previousBase, state string
	err = tx.QueryRow(ctx, `SELECT profile_kind,subscription_base,state FROM bot_profiles WHERE tenant_id=$1::uuid FOR UPDATE`, tenant).Scan(&kind, &previousBase, &state)
	if err == nil {
		var same bool
		err = tx.QueryRow(ctx, `SELECT count(*)=1 AND COALESCE(bool_and(source_uuid=$2::uuid AND plan_id=$2::uuid AND source_present),false) FROM bot_squads WHERE tenant_id=$1::uuid`, tenant, plan).Scan(&same)
		if err != nil {
			return out, err
		}
		if kind != "native" || previousBase != base || state != "active" || !same {
			return out, ErrBotBridgeConflict
		}
	} else if errors.Is(err, pgx.ErrNoRows) {
		var migrated bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remnawave_imports WHERE tenant_id=$1::uuid)`, tenant).Scan(&migrated)
		if err != nil {
			return out, err
		}
		if migrated {
			return out, ErrBotBridgeConflict
		}
		_, err = tx.Exec(ctx, `INSERT INTO bot_profiles(tenant_id,profile_kind,subscription_base,state,source_identity_reviewed,activated_at) VALUES($1::uuid,'native',$2,'active',true,now())`, tenant, base)
		if err != nil {
			return out, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO bot_squads(tenant_id,source_uuid,name,plan_id) VALUES($1::uuid,$2::uuid,$3,$2::uuid)`, tenant, plan, name)
		if err != nil {
			return out, err
		}
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'bot_bridge.native_configured',$2,$3,jsonb_build_object('plan_id',$4::text))`, tenant, actor, actorID, plan)
		if err != nil {
			return out, err
		}
	} else {
		return out, err
	}
	out = NativeBotSetup{TenantID: tenant, SubscriptionBase: base, AccessPlanID: plan, SquadID: plan}
	return out, tx.Commit(ctx)
}

func nativeBotAliasClientTx(ctx context.Context, tx pgx.Tx, alias string) (string, error) {
	if !importedAlias.MatchString(alias) {
		return "", ErrNotFound
	}
	var client, tenant string
	err := tx.QueryRow(ctx, `SELECT c.id::text,c.tenant_id::text FROM bot_subscription_aliases a
 JOIN bot_accounts b ON b.tenant_id=a.tenant_id AND b.legacy_id=a.legacy_id
 JOIN bot_profiles p ON p.tenant_id=b.tenant_id
 JOIN vpn_clients c ON c.id=b.client_id AND c.tenant_id=b.tenant_id
 WHERE a.alias=$1 AND a.state='active' AND b.source_present AND b.deleted_at IS NULL AND NOT c.remnawave_hold
 AND p.profile_kind='native' AND p.import_id IS NULL AND p.state IN ('active','paused') AND p.source_identity_reviewed AND p.activated_at IS NOT NULL`, alias).Scan(&client, &tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return "", ErrNotFound
	}
	return client, nil
}

// The opaque alias authenticates only this subscription, never a tenant API.
func (p *Postgres) ResolveNativeBotAlias(ctx context.Context, alias string) (string, error) {
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	client, err := nativeBotAliasClientTx(ctx, tx, alias)
	if err != nil {
		return "", err
	}
	return client, tx.Commit(ctx)
}
