package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/model"
)

const vpnClientColumns = `id::text,tenant_id::text,name,vless_uuid::text,status,
 CASE WHEN status='disabled' THEN 'disabled' WHEN expires_at IS NOT NULL AND expires_at<=now() THEN 'expired'
 WHEN vpn_client_quota_exceeded(vpn_clients.id) THEN 'quota_exceeded'
 ELSE 'active' END,
 expires_at,created_at,updated_at,remnawave_hold`

// Serialize tariff membership and client eligibility changes within a tenant.
// The namespace is fixed; hash collisions only cause extra serialization.
func lockTenantAccess(ctx context.Context, tx pgx.Tx, tenant string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103504,hashtext($1))`, tenant)
	return err
}
func sameExpiry(a, b *time.Time) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Equal(*b)
}
func (p *Postgres) mutateVPNClient(ctx context.Context, id string, name, status *string, expiresAt *time.Time, setExpiry bool) (model.VPNClient, error) {
	var out model.VPNClient
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM vpn_clients WHERE id=$1::uuid`, id).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return out, ErrNotFound
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	before, err := scanVPNClient(tx.QueryRow(ctx, `SELECT `+vpnClientColumns+` FROM vpn_clients WHERE id=$1::uuid FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	newName, newStatus, newExpiry := before.Name, before.Status, before.ExpiresAt
	if name != nil {
		newName = *name
	}
	if status != nil {
		newStatus = *status
	}
	if newStatus == "active" {
		if before.RemnawaveHold {
			return out, ErrRemnawaveHold
		}
	}
	if setExpiry {
		newExpiry = expiresAt
	}
	if newName == before.Name && newStatus == before.Status && sameExpiry(newExpiry, before.ExpiresAt) {
		return before, tx.Commit(ctx)
	}
	out, err = scanVPNClient(tx.QueryRow(ctx, `UPDATE vpn_clients SET name=$2,status=$3,expires_at=$4,updated_at=now() WHERE id=$1::uuid RETURNING `+vpnClientColumns, id, newName, newStatus, newExpiry))
	if err != nil {
		return out, err
	}
	rebuilds := 0
	if (before.EffectiveStatus == "active") != (out.EffectiveStatus == "active") || out.EffectiveStatus != "active" && (before.Status != newStatus || !sameExpiry(before.ExpiresAt, newExpiry)) {
		// Include current desired-state presence, so a legacy detached grant can
		// still be revoked. All target locks are acquired in stable node order.
		rows, err := tx.Query(ctx, `SELECT n.id::text FROM nodes n WHERE n.tenant_id=$1::uuid AND n.status<>'retired' AND (vpn_node_cascade_client(n.id,$2::uuid,$3::text) OR
          EXISTS(SELECT 1 FROM vpn_effective_client_services cs JOIN vpn_services s ON s.id=cs.service_id AND s.tenant_id=cs.tenant_id WHERE cs.client_id=$2::uuid AND s.node_id=n.id AND s.enabled)
          OR EXISTS(SELECT 1 FROM desired_states ds,jsonb_array_elements(COALESCE(ds.document->'services','[]'::jsonb)) s,jsonb_array_elements(COALESCE(s->'clients','[]'::jsonb)) u WHERE ds.node_id=n.id AND ds.generation=n.desired_generation AND u->>'id'=$3)) ORDER BY n.id`, tenant, id, before.VLESSUUID)
		if err != nil {
			return out, err
		}
		nodes := []string{}
		for rows.Next() {
			var node string
			if err = rows.Scan(&node); err != nil {
				rows.Close()
				return out, err
			}
			nodes = append(nodes, node)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return out, err
		}
		for _, node := range nodes {
			state, release, err := buildNodeDesiredStateTx(ctx, tx, node)
			if err != nil {
				return out, err
			}
			if err = saveDesiredStateTx(ctx, tx, node, state, release); err != nil {
				return out, err
			}
			rebuilds++
		}
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.updated',$2,$3,jsonb_build_object('client_id',$4::text,'rebuild_count',$5::integer))`, tenant, actorType, actorID, id, rebuilds)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

const inactiveDesiredPredicate = `EXISTS(
 SELECT 1 FROM desired_states ds,
 jsonb_array_elements(COALESCE(ds.document->'services','[]'::jsonb)) s,
 jsonb_array_elements(COALESCE(s->'clients','[]'::jsonb)) u,
 vpn_clients c, vpn_services managed
 WHERE ds.node_id=n.id AND ds.generation=n.desired_generation
 AND c.tenant_id=n.tenant_id AND (u->>'stats_key'=c.id::text OR (COALESCE(u->>'stats_key','')='' AND u->>'id'=CASE WHEN managed.protocol IN ('openvpn','wireguard','amneziawg','pptp') THEN c.id::text ELSE c.vless_uuid::text END))
 AND managed.id::text=s->>'id' AND managed.node_id=n.id AND managed.tenant_id=n.tenant_id
 AND (c.status='disabled' OR c.expires_at<=now() OR vpn_client_quota_exceeded(c.id)
 OR NOT managed.enabled OR NOT EXISTS(
 SELECT 1 FROM vpn_effective_client_services e WHERE e.client_id=c.id AND e.service_id=managed.id AND e.tenant_id=n.tenant_id)))`

const activeMissingDesiredPredicate = `EXISTS(
 SELECT 1 FROM vpn_effective_client_services e
 JOIN vpn_clients c ON c.id=e.client_id AND c.tenant_id=e.tenant_id
 JOIN vpn_services managed ON managed.id=e.service_id AND managed.tenant_id=e.tenant_id
 WHERE managed.node_id=n.id AND managed.enabled AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now())
 AND NOT vpn_client_quota_exceeded(c.id)
 AND NOT EXISTS(SELECT 1 FROM desired_states ds,jsonb_array_elements(COALESCE(ds.document->'services','[]'::jsonb)) service,jsonb_array_elements(COALESCE(service->'clients','[]'::jsonb)) member WHERE ds.node_id=n.id AND ds.generation=n.desired_generation AND service->>'id'=managed.id::text AND (member->>'stats_key'=c.id::text OR (COALESCE(member->>'stats_key','')='' AND member->>'id'=CASE WHEN managed.protocol IN ('openvpn','wireguard','amneziawg','pptp') THEN c.id::text ELSE c.vless_uuid::text END))))`

const accessMismatchPredicate = `n.status<>'retired' AND (` + inactiveDesiredPredicate + ` OR ` + activeMissingDesiredPredicate + `)`

// Reconcile only nodes whose current desired state still contains an inactive
// client. After one successful rebuild the node is no longer selected.
func (p *Postgres) ReconcileInactiveVPNClients(ctx context.Context) (int, error) {
	rows, err := p.Pool.Query(ctx, `SELECT n.id::text FROM nodes n WHERE `+accessMismatchPredicate+` ORDER BY n.id LIMIT 100`)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	count := 0
	var failures error
	for _, id := range ids {
		changed, err := p.reconcileInactiveNode(ctx, id)
		if err != nil {
			failures = errors.Join(failures, err)
			continue
		}
		if changed {
			count++
		}
	}
	return count, failures
}
func (p *Postgres) reconcileInactiveNode(ctx context.Context, id string) (bool, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	if err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM nodes WHERE id=$1::uuid`, id).Scan(&tenant); errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return false, err
	}
	var locked string
	if err = tx.QueryRow(ctx, `SELECT id::text FROM nodes WHERE id=$1::uuid FOR UPDATE`, id).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	var needed bool
	if err = tx.QueryRow(ctx, `SELECT `+accessMismatchPredicate+` FROM nodes n WHERE n.id=$1::uuid`, id).Scan(&needed); err != nil {
		return false, err
	}
	if !needed {
		return false, tx.Commit(ctx)
	}
	state, release, err := buildNodeDesiredStateTx(ctx, tx, id)
	if err != nil {
		return false, err
	}
	if err = saveDesiredStateTx(ctx, tx, id, state, release); err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_access.inactive_reconciled','system','access-reconciler',jsonb_build_object('node_id',$2::text,'generation',$3::bigint))`, tenant, id, state.Generation)
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
