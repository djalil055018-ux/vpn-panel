package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
)

var ErrTrafficPolicyConflict = errors.New("traffic reset policy does not match this operation")

// A limit edit never initializes or resets the accounting baseline. Creation is
// restricted to the reviewed held migration preparation below.
func (p *Postgres) SetVPNClientContinuousLimit(ctx context.Context, id string, limit int64) (model.VPNClientUsage, error) {
	if limit < 0 || limit > maxTrafficCounter {
		return model.VPNClientUsage{}, ErrTenantQuota
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant, credential string
	var held bool
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,vless_uuid::text,remnawave_hold FROM vpn_clients WHERE id=$1::uuid`, id).Scan(&tenant, &credential, &held)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNClientUsage{}, ErrNotFound
	}
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	if !tenantScopeAllowed(ctx, tenant) || held && !remnawaveOwnerAllowed(ctx) {
		return model.VPNClientUsage{}, ErrNotFound
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return model.VPNClientUsage{}, err
	}
	before, err := scanVPNClientUsage(tx.QueryRow(ctx, vpnClientUsageQuery, id))
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	if before.ResetPolicy != "NO_RESET" {
		return model.VPNClientUsage{}, ErrTrafficPolicyConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET limit_bytes=$2,updated_at=now() WHERE client_id=$1::uuid`, id, limit); err != nil {
		return model.VPNClientUsage{}, err
	}
	after, err := scanVPNClientUsage(tx.QueryRow(ctx, vpnClientUsageQuery, id))
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	rebuilds := 0
	if before.QuotaExceeded != after.QuotaExceeded {
		rebuilds, err = rebuildClientAccessNodes(ctx, tx, id, credential)
		if err != nil {
			return model.VPNClientUsage{}, err
		}
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.continuous_limit_updated',$2,$3,jsonb_build_object('client_id',$4::text,'limit_bytes',$5::bigint,'rebuild_count',$6::integer))`, tenant, actorType, actorID, id, limit, rebuilds)
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	return after, tx.Commit(ctx)
}

type RemnawaveQuotaPreparation struct {
	ImportID        string `json:"import_id"`
	InventorySHA256 string `json:"inventory_sha256"`
	Prepared        int    `json:"prepared"`
	Existing        int    `json:"existing"`
	Deleted         int    `json:"deleted"`
	CutoverReady    bool   `json:"cutover_ready"`
}

// Preserve the source used counter without issuing credentials, memberships or
// subscriptions. Replays must match exactly; a newer source snapshot requires a
// reviewed delta, never an implicit reset of this accounting baseline.
func (p *Postgres) PrepareRemnawaveNoResetQuota(ctx context.Context, id, tenant, reviewedSHA string) (RemnawaveQuotaPreparation, error) {
	out := RemnawaveQuotaPreparation{ImportID: id}
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var origin string
	err = tx.QueryRow(ctx, `SELECT source_origin FROM remnawave_imports WHERE id=$1::uuid AND tenant_id=$2::uuid AND state='held'`, id, tenant).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103509,hashtext($1))`, origin); err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	var raw []byte
	var digest string
	if err = tx.QueryRow(ctx, `SELECT r.inventory,h.inventory_sha256 FROM `+remnawaveCurrentFrom+` WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid AND i.state='held' FOR UPDATE OF h`, id, tenant).Scan(&raw, &digest); errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if digest != reviewedSHA {
		return out, ErrRemnawaveReview
	}
	inv, report, err := remnawave.Parse(raw)
	if err != nil {
		return out, err
	}
	if report.SHA256 != digest {
		return out, ErrRemnawaveConflict
	}
	out.InventorySHA256 = digest
	for _, u := range inv.Users {
		if u.TrafficLimitStrategy != "NO_RESET" || *u.TrafficLimitBytes > maxTrafficCounter || *u.Traffic.Used > maxTrafficCounter {
			return out, ErrTrafficPolicyConflict
		}
		var client *string
		var deleted bool
		err = tx.QueryRow(ctx, `SELECT client_id::text,deleted_at IS NOT NULL FROM remnawave_import_clients WHERE import_id=$1::uuid AND source_user_id=$2`, id, u.ID).Scan(&client, &deleted)
		if err != nil {
			return out, ErrRemnawaveConflict
		}
		if client == nil && deleted {
			out.Deleted++
			continue
		}
		if client == nil || deleted {
			return out, ErrRemnawaveConflict
		}
		var eligible bool
		if err = tx.QueryRow(ctx, `SELECT remnawave_hold AND status='disabled' AND tenant_id=$2::uuid AND NOT EXISTS(SELECT 1 FROM node_client_traffic_cursors WHERE client_id=$1::uuid) FROM vpn_clients WHERE id=$1::uuid`, *client, tenant).Scan(&eligible); err != nil {
			return out, err
		}
		if !eligible {
			return out, ErrRemnawaveConflict
		}
		var limit, baseline, up, down int64
		var at time.Time
		err = tx.QueryRow(ctx, `SELECT limit_bytes,baseline_bytes,baseline_at,uplink_bytes,downlink_bytes FROM vpn_client_continuous_quotas WHERE client_id=$1::uuid`, *client).Scan(&limit, &baseline, &at, &up, &down)
		if err == nil {
			if limit != *u.TrafficLimitBytes || baseline != *u.Traffic.Used || !at.Equal(inv.CapturedAt.Truncate(time.Microsecond)) || up != 0 || down != 0 {
				return out, ErrRemnawaveConflict
			}
			out.Existing++
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO vpn_client_continuous_quotas(client_id,limit_bytes,baseline_bytes,baseline_at) VALUES($1::uuid,$2,$3,$4)`, *client, *u.TrafficLimitBytes, *u.Traffic.Used, inv.CapturedAt.Truncate(time.Microsecond)); err != nil {
			return out, err
		}
		out.Prepared++
	}
	if out.Prepared > 0 {
		actorType, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'remnawave.quota_prepared',$2,$3,jsonb_build_object('import_id',$4::text,'inventory_sha256',$5::text,'client_count',$6::integer,'state','held'))`, tenant, actorType, actorID, id, digest, out.Prepared)
		if err != nil {
			return out, err
		}
	}
	return out, tx.Commit(ctx)
}
