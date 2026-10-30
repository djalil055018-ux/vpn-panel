package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/remnawave"
)

var ErrRemnawaveBase = errors.New("Remnawave current inventory changed; review a new delta")

type RemnawaveDeltaApplied struct {
	ImportID        string `json:"import_id"`
	InventorySHA256 string `json:"inventory_sha256"`
	Applied         bool   `json:"applied"`
	Created         int    `json:"created"`
	Updated         int    `json:"updated"`
	SourceAbsent    int    `json:"source_absent"`
	Deleted         int    `json:"deleted"`
	QuotasRefreshed int    `json:"quotas_refreshed"`
	CutoverReady    bool   `json:"cutover_ready"`
}

type remnawaveHistoricalUser struct {
	user     remnawave.User
	captured time.Time
}

// History reserves source identities even after a target deletion or source
// removal. A reviewed credential rotation can only belong to the same source ID.
func remnawaveHistory(ctx context.Context, tx pgx.Tx, id string, next remnawave.Inventory) (map[int64]remnawaveHistoricalUser, error) {
	rows, err := tx.Query(ctx, `SELECT inventory,inventory_sha256 FROM remnawave_inventory_revisions WHERE import_id=$1::uuid ORDER BY sequence_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	last := map[int64]remnawaveHistoricalUser{}
	identities := map[string]int64{}
	accept := func(u remnawave.User) error {
		if prior, ok := last[u.ID]; ok {
			if !prior.user.CreatedAt.Equal(u.CreatedAt) || !strings.EqualFold(prior.user.UUID, u.UUID) {
				return ErrRemnawaveConflict
			}
		}
		for _, key := range []string{"vless:" + strings.ToLower(u.VLESSUUID), "subscription:" + u.ShortUUID, "source:" + strings.ToLower(u.UUID)} {
			if key == "source:" {
				continue
			}
			if owner, ok := identities[key]; ok && owner != u.ID {
				return ErrRemnawaveConflict
			}
			identities[key] = u.ID
		}
		return nil
	}
	for rows.Next() {
		var raw []byte
		var digest string
		if err = rows.Scan(&raw, &digest); err != nil {
			return nil, err
		}
		inv, report, e := remnawave.Parse(raw)
		if e != nil || report.SHA256 != digest || inv.SourceOrigin != next.SourceOrigin {
			return nil, ErrRemnawaveConflict
		}
		for _, u := range inv.Users {
			if e = accept(u); e != nil {
				return nil, e
			}
			last[u.ID] = remnawaveHistoricalUser{u, inv.CapturedAt.Truncate(time.Microsecond)}
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for _, u := range next.Users {
		if err = accept(u); err != nil {
			return nil, err
		}
	}
	return last, nil
}

type remnawaveHeldMapping struct {
	source           int64
	client           *string
	status           string
	present, deleted bool
	quota            bool
}

// ApplyRemnawaveHeldDelta never activates clients or writes to source nodes. It
// requires an optimistic base digest and exact reviewed bytes, serializes against
// account deletion and accounting, and rejects any unexpected target changes.
func (p *Postgres) ApplyRemnawaveHeldDelta(ctx context.Context, id, tenant, baseSHA, reviewedSHA string, raw []byte) (out RemnawaveDeltaApplied, err error) {
	out.ImportID = id
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	inv, report, err := remnawave.Parse(raw)
	if err != nil {
		return out, err
	}
	if reviewedSHA != report.SHA256 {
		return out, ErrRemnawaveReview
	}
	if len(baseSHA) != 64 || strings.Trim(baseSHA, "0123456789abcdef") != "" {
		return out, ErrRemnawaveBase
	}
	out.InventorySHA256 = report.SHA256
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	defer func() {
		var e *pgconn.PgError
		if errors.As(err, &e) && e.Code == "23505" {
			err = ErrRemnawaveConflict
		}
	}()
	var origin string
	err = tx.QueryRow(ctx, `SELECT source_origin FROM remnawave_imports WHERE id=$1::uuid AND tenant_id=$2::uuid AND state='held'`, id, tenant).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if origin != inv.SourceOrigin {
		return out, remnawave.ErrDeltaSource
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103509,hashtext($1))`, origin); err != nil {
		return out, err
	}
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	var before []byte
	var digest string
	var parent *string
	err = tx.QueryRow(ctx, `SELECT r.inventory,h.inventory_sha256,r.parent_sha256 FROM `+remnawaveCurrentFrom+` WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid AND i.state='held' FOR UPDATE OF h`, id, tenant).Scan(&before, &digest, &parent)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	replay := digest == report.SHA256
	// An exact retry with its original base is safe only while that revision is
	// still current. Replaying an older accepted revision cannot move the head back.
	if baseSHA != digest && !(replay && parent != nil && baseSHA == *parent) {
		return out, ErrRemnawaveBase
	}
	delta, err := remnawave.Compare(before, raw)
	if err != nil {
		return out, err
	}
	if !replay && !delta.AfterCapturedAt.After(delta.BeforeCapturedAt) {
		return out, remnawave.ErrDeltaSource
	}
	history, err := remnawaveHistory(ctx, tx, id, inv)
	if err != nil {
		return out, err
	}
	old, _, err := remnawave.Parse(before)
	if err != nil {
		return out, err
	}
	present := map[int64]bool{}
	for _, u := range old.Users {
		present[u.ID] = true
	}
	incoming := map[int64]remnawave.User{}
	for _, u := range inv.Users {
		incoming[u.ID] = u
	}
	rows, err := tx.Query(ctx, `SELECT source_user_id,client_id::text,source_status,source_present,deleted_at IS NOT NULL FROM remnawave_import_clients WHERE import_id=$1::uuid ORDER BY source_user_id`, id)
	if err != nil {
		return out, err
	}
	mappings := map[int64]remnawaveHeldMapping{}
	for rows.Next() {
		var m remnawaveHeldMapping
		if err = rows.Scan(&m.source, &m.client, &m.status, &m.present, &m.deleted); err != nil {
			rows.Close()
			return out, err
		}
		mappings[m.source] = m
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(history) != len(mappings) {
		return out, ErrRemnawaveConflict
	}
	for source, m := range mappings {
		prev, exists := history[source]
		if !exists || m.present != present[source] || m.status != prev.user.Status {
			return out, ErrRemnawaveConflict
		}
		if m.deleted && m.client == nil {
			if _, ok := incoming[source]; ok {
				out.Deleted++
			}
			continue
		}
		if m.deleted || m.client == nil {
			return out, ErrRemnawaveConflict
		}
		var eligible bool
		err = tx.QueryRow(ctx, `SELECT c.tenant_id=$2::uuid AND c.remnawave_hold AND c.status='disabled'
   AND c.name=$3 AND c.vless_uuid=$4::uuid AND c.expires_at=$5
   AND NOT EXISTS(SELECT 1 FROM vpn_client_limits WHERE client_id=c.id AND (monthly_bytes<>0 OR device_limit<>0))
   AND NOT EXISTS(SELECT 1 FROM vpn_effective_client_services WHERE client_id=c.id)
   AND NOT EXISTS(SELECT 1 FROM vpn_client_subscriptions WHERE client_id=c.id)
   AND NOT EXISTS(SELECT 1 FROM node_client_traffic_cursors WHERE client_id=c.id)
   AND NOT EXISTS(SELECT 1 FROM vpn_client_usage_monthly WHERE client_id=c.id)
   FROM vpn_clients c WHERE c.id=$1::uuid`, *m.client, tenant, prev.user.Username, prev.user.VLESSUUID, prev.user.ExpireAt).Scan(&eligible)
		if err != nil {
			return out, err
		}
		if !eligible {
			return out, ErrRemnawaveConflict
		}
		var limit, baseline, up, down int64
		var at time.Time
		err = tx.QueryRow(ctx, `SELECT limit_bytes,baseline_bytes,baseline_at,uplink_bytes,downlink_bytes FROM vpn_client_continuous_quotas WHERE client_id=$1::uuid`, *m.client).Scan(&limit, &baseline, &at, &up, &down)
		if err == nil {
			if prev.user.TrafficLimitStrategy != "NO_RESET" || limit != *prev.user.TrafficLimitBytes || baseline != *prev.user.Traffic.Used || !at.Equal(prev.captured) || up != 0 || down != 0 {
				return out, ErrRemnawaveConflict
			}
			m.quota = true
			mappings[source] = m
			if next, ok := incoming[source]; ok && (next.TrafficLimitStrategy != "NO_RESET" || *next.TrafficLimitBytes > maxTrafficCounter || *next.Traffic.Used > maxTrafficCounter) {
				return out, ErrTrafficPolicyConflict
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
	}
	if replay {
		return out, tx.Commit(ctx)
	}
	added := 0
	for source := range incoming {
		if _, exists := mappings[source]; !exists {
			added++
		}
	}
	limits, err := scanTenantLimits(tx.QueryRow(ctx, tenantLimitsQuery, tenant))
	if err != nil {
		return out, err
	}
	if limits.MaxClients > 0 && added > limits.MaxClients-limits.Clients {
		return out, ErrTenantQuota
	}
	// Preserve removed source accounts as explicitly absent held records. Target
	// deletions remain durable tombstones even if that source ID returns later.
	if _, err = tx.Exec(ctx, `UPDATE remnawave_import_clients SET source_present=false WHERE import_id=$1::uuid`, id); err != nil {
		return out, err
	}
	for source, m := range mappings {
		if _, exists := incoming[source]; exists {
			continue
		}
		out.SourceAbsent++
		if m.client != nil && m.quota {
			if _, err = tx.Exec(ctx, `DELETE FROM vpn_client_continuous_quotas WHERE client_id=$1::uuid`, *m.client); err != nil {
				return out, err
			}
		}
	}
	for _, u := range inv.Users {
		m, exists := mappings[u.ID]
		if exists {
			if _, err = tx.Exec(ctx, `UPDATE remnawave_import_clients SET source_status=$3,source_present=true WHERE import_id=$1::uuid AND source_user_id=$2`, id, u.ID, u.Status); err != nil {
				return out, err
			}
			if m.deleted {
				continue
			}
			if _, err = tx.Exec(ctx, `UPDATE vpn_clients SET name=$2,vless_uuid=$3::uuid,expires_at=$4,updated_at=now() WHERE id=$1::uuid`, *m.client, u.Username, u.VLESSUUID, u.ExpireAt); err != nil {
				return out, err
			}
			out.Updated++
			if m.quota {
				if _, err = tx.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET limit_bytes=$2,baseline_bytes=$3,baseline_at=$4,updated_at=now() WHERE client_id=$1::uuid`, *m.client, *u.TrafficLimitBytes, *u.Traffic.Used, inv.CapturedAt.Truncate(time.Microsecond)); err != nil {
					return out, err
				}
				out.QuotasRefreshed++
			}
		} else {
			var client string
			if err = tx.QueryRow(ctx, `INSERT INTO vpn_clients(tenant_id,name,vless_uuid,status,expires_at,remnawave_hold) VALUES($1::uuid,$2,$3::uuid,'disabled',$4,true) RETURNING id::text`, tenant, u.Username, u.VLESSUUID, u.ExpireAt).Scan(&client); err != nil {
				return out, err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO remnawave_import_clients(import_id,source_user_id,source_status,client_id) VALUES($1::uuid,$2,$3,$4::uuid)`, id, u.ID, u.Status, client); err != nil {
				return out, err
			}
			out.Created++
		}
	}
	summary, err := json.Marshal(report)
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO remnawave_inventory_revisions(import_id,inventory_sha256,parent_sha256,inventory,report,captured_at) VALUES($1::uuid,$2,$3,$4,$5::jsonb,$6)`, id, report.SHA256, digest, raw, summary, inv.CapturedAt); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE remnawave_import_heads SET inventory_sha256=$2 WHERE import_id=$1::uuid`, id, report.SHA256); err != nil {
		return out, err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'remnawave.delta_applied',$2,$3,jsonb_build_object('import_id',$4::text,'base_sha256',$5::text,'inventory_sha256',$6::text,'created',$7::integer,'updated',$8::integer,'source_absent',$9::integer,'deleted',$10::integer,'quotas_refreshed',$11::integer,'state','held'))`, tenant, actorType, actorID, id, digest, report.SHA256, out.Created, out.Updated, out.SourceAbsent, out.Deleted, out.QuotasRefreshed)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	out.Applied = true
	return out, nil
}
