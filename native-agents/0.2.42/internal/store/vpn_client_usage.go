package store

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

const maxTrafficCounter int64 = 9000000000000000

func trafficPeriod(at time.Time) time.Time {
	at = at.UTC()
	return time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func trafficDelta(current, previous int64) int64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func saveClientTraffic(ctx context.Context, tx pgx.Tx, nodeID string, samples []model.ClientTraffic, observedAt time.Time, epoch string, sequence int64) ([]string, error) {
	if len(samples) == 0 {
		return nil, nil
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].ClientID < samples[j].ClientID })
	period := trafficPeriod(observedAt)
	crossed := []string{}
	for _, sample := range samples {
		var clientID string
		err := tx.QueryRow(ctx, `SELECT c.id::text FROM vpn_clients c JOIN nodes n ON n.tenant_id=c.tenant_id WHERE n.id=$1::uuid AND c.id=$2::uuid`, nodeID, sample.ClientID).Scan(&clientID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103505,hashtext($1))`, clientID); err != nil {
			return nil, err
		}
		var previousUp, previousDown int64
		var previousEpoch string
		var previousSequence int64
		err = tx.QueryRow(ctx, `SELECT uplink_bytes,downlink_bytes,counter_epoch,sample_sequence FROM node_client_traffic_cursors WHERE node_id=$1::uuid AND client_id=$2::uuid FOR UPDATE`, nodeID, clientID).Scan(&previousUp, &previousDown, &previousEpoch, &previousSequence)
		if errors.Is(err, pgx.ErrNoRows) {
			previousUp, previousDown = 0, 0
		} else if err != nil {
			return nil, err
		}
		// Once ordered reports have started, delayed legacy and replayed reports
		// cannot overwrite a newer cursor or make old address counts look fresh.
		if previousSequence > 0 && sequence <= previousSequence {
			continue
		}
		if previousEpoch != "" && previousEpoch == epoch && (sample.Uplink < previousUp || sample.Downlink < previousDown) {
			continue
		}
		var beforeExceeded bool
		if err = tx.QueryRow(ctx, `SELECT vpn_client_quota_exceeded($1::uuid)`, clientID).Scan(&beforeExceeded); errors.Is(err, pgx.ErrNoRows) {
			beforeExceeded = false
		} else if err != nil {
			return nil, err
		}
		upDelta := trafficDelta(sample.Uplink, previousUp)
		downDelta := trafficDelta(sample.Downlink, previousDown)
		if previousEpoch != "" && epoch != previousEpoch {
			upDelta = sample.Uplink
			downDelta = sample.Downlink
		}
		_, err = tx.Exec(ctx, `INSERT INTO node_client_traffic_cursors(node_id,client_id,uplink_bytes,downlink_bytes,active_ips,observed_at,counter_epoch,sample_sequence,active_ips_known,first_connected_at,last_online_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,CASE WHEN $10::boolean THEN $6::timestamptz ELSE NULL END,CASE WHEN $10::boolean THEN $6::timestamptz ELSE NULL END) ON CONFLICT(node_id,client_id) DO UPDATE SET uplink_bytes=EXCLUDED.uplink_bytes,downlink_bytes=EXCLUDED.downlink_bytes,active_ips=EXCLUDED.active_ips,observed_at=EXCLUDED.observed_at,counter_epoch=EXCLUDED.counter_epoch,sample_sequence=EXCLUDED.sample_sequence,active_ips_known=EXCLUDED.active_ips_known,first_connected_at=LEAST(node_client_traffic_cursors.first_connected_at,EXCLUDED.first_connected_at),last_online_at=GREATEST(node_client_traffic_cursors.last_online_at,EXCLUDED.last_online_at)`, nodeID, clientID, sample.Uplink, sample.Downlink, sample.ActiveIPs, observedAt, epoch, sequence, !sample.ActiveIPsUnavailable, upDelta > 0 || downDelta > 0 || (!sample.ActiveIPsUnavailable && sample.ActiveIPs > 0))
		if err != nil {
			return nil, err
		}
		if upDelta > 0 || downDelta > 0 {
			_, err = tx.Exec(ctx, `INSERT INTO vpn_client_usage_monthly(client_id,period_start,uplink_bytes,downlink_bytes) VALUES($1::uuid,$2::date,$3,$4) ON CONFLICT(client_id,period_start) DO UPDATE SET uplink_bytes=LEAST($5::bigint,vpn_client_usage_monthly.uplink_bytes+EXCLUDED.uplink_bytes),downlink_bytes=LEAST($5::bigint,vpn_client_usage_monthly.downlink_bytes+EXCLUDED.downlink_bytes),updated_at=now()`, clientID, period, upDelta, downDelta, maxTrafficCounter)
			if err != nil {
				return nil, err
			}
			_, err = tx.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET uplink_bytes=LEAST($4::bigint,uplink_bytes+$2::bigint),downlink_bytes=LEAST($4::bigint,downlink_bytes+$3::bigint),updated_at=now() WHERE client_id=$1::uuid`, clientID, upDelta, downDelta, maxTrafficCounter)
			if err != nil {
				return nil, err
			}
		}
		var afterExceeded bool
		if err = tx.QueryRow(ctx, `SELECT vpn_client_quota_exceeded($1::uuid)`, clientID).Scan(&afterExceeded); errors.Is(err, pgx.ErrNoRows) {
			afterExceeded = false
		} else if err != nil {
			return nil, err
		}
		if !beforeExceeded && afterExceeded {
			crossed = append(crossed, clientID)
		}
	}
	// Keep the cumulative baseline while the node and client exist. Expiring it
	// would bill the entire old counter again when an idle client returns.
	return crossed, nil
}

func scanVPNClientUsage(row pgx.Row) (model.VPNClientUsage, error) {
	var out model.VPNClientUsage
	var observed *time.Time
	err := row.Scan(&out.ClientID, &out.PeriodStart, &out.UplinkBytes, &out.DownlinkBytes, &out.MonthlyLimitBytes, &out.ActiveIPs, &out.DeviceLimit, &observed, &out.UpdatedAt, &out.TrafficLimitBytes, &out.ResetPolicy, &out.ImportedBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.UsedBytes = out.ImportedBytes + out.UplinkBytes + out.DownlinkBytes
	if out.TrafficLimitBytes > 0 {
		out.QuotaExceeded = out.UsedBytes >= out.TrafficLimitBytes
		out.RemainingBytes = out.TrafficLimitBytes - out.UsedBytes
		if out.RemainingBytes < 0 {
			out.RemainingBytes = 0
		}
	}
	out.DeviceWarning = out.DeviceLimit > 0 && out.ActiveIPs != nil && *out.ActiveIPs > out.DeviceLimit
	out.LastObservedAt = observed
	return out, nil
}

const vpnClientUsageQuery = `SELECT c.id::text,
 COALESCE(q.baseline_at,date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),
 CASE WHEN q.client_id IS NULL THEN COALESCE(u.uplink_bytes,0) ELSE q.uplink_bytes END,
 CASE WHEN q.client_id IS NULL THEN COALESCE(u.downlink_bytes,0) ELSE q.downlink_bytes END,
 CASE WHEN q.client_id IS NULL THEN COALESCE(l.monthly_bytes,0) ELSE 0 END,
 (SELECT CASE WHEN bool_or(NOT cur.active_ips_known) THEN NULL ELSE LEAST(COALESCE(sum(cur.active_ips),0),2147483647)::integer END FROM node_client_traffic_cursors cur WHERE cur.client_id=c.id AND cur.observed_at>now()-interval '2 minutes'),
 COALESCE(l.device_limit,0),(SELECT max(cur.observed_at) FROM node_client_traffic_cursors cur WHERE cur.client_id=c.id),
 GREATEST(COALESCE(q.updated_at,u.updated_at,c.updated_at),COALESCE(l.updated_at,c.updated_at)),
 COALESCE(q.limit_bytes,l.monthly_bytes,0),CASE WHEN q.client_id IS NULL THEN 'MONTH' ELSE 'NO_RESET' END,COALESCE(q.baseline_bytes,0)
 FROM vpn_clients c LEFT JOIN vpn_client_limits l ON l.client_id=c.id
 LEFT JOIN vpn_client_continuous_quotas q ON q.client_id=c.id
 LEFT JOIN vpn_client_usage_monthly u ON u.client_id=c.id AND u.period_start=date_trunc('month',now() AT TIME ZONE 'UTC')::date WHERE c.id=$1::uuid`

func (p *Postgres) VPNClientUsage(ctx context.Context, clientID string) (model.VPNClientUsage, error) {
	out, err := scanVPNClientUsage(p.Pool.QueryRow(ctx, vpnClientUsageQuery, clientID))
	if err != nil {
		return out, err
	}
	client, err := p.GetVPNClient(ctx, clientID)
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	if !tenantScopeAllowed(ctx, client.TenantID) {
		return model.VPNClientUsage{}, ErrNotFound
	}
	return out, nil
}

func clientAccessNodes(ctx context.Context, tx pgx.Tx, clientID, credential string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT n.id::text FROM nodes n JOIN vpn_clients c ON c.tenant_id=n.tenant_id WHERE c.id=$1::uuid AND n.status<>'retired' AND (vpn_node_cascade_client(n.id,c.id,$2::text) OR EXISTS(SELECT 1 FROM vpn_effective_client_services e JOIN vpn_services s ON s.id=e.service_id AND s.tenant_id=e.tenant_id WHERE e.client_id=c.id AND s.node_id=n.id AND s.enabled) OR EXISTS(SELECT 1 FROM desired_states ds,jsonb_array_elements(COALESCE(ds.document->'services','[]'::jsonb)) service,jsonb_array_elements(COALESCE(service->'clients','[]'::jsonb)) member WHERE ds.node_id=n.id AND ds.generation=n.desired_generation AND member->>'id'=$2::text)) ORDER BY n.id::text`, clientID, credential)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func rebuildClientAccessNodes(ctx context.Context, tx pgx.Tx, clientID, credential string) (int, error) {
	nodes, err := clientAccessNodes(ctx, tx, clientID, credential)
	if err != nil {
		return 0, err
	}
	for _, node := range nodes {
		state, release, err := buildNodeDesiredStateTx(ctx, tx, node)
		if err != nil {
			return 0, err
		}
		if err = saveDesiredStateTx(ctx, tx, node, state, release); err != nil {
			return 0, err
		}
	}
	return len(nodes), nil
}

func (p *Postgres) SetVPNClientLimits(ctx context.Context, clientID string, monthlyBytes int64, deviceLimit int) (model.VPNClientUsage, error) {
	if monthlyBytes < 0 || monthlyBytes > maxTrafficCounter || deviceLimit < 0 || deviceLimit > 1000 {
		return model.VPNClientUsage{}, ErrTenantQuota
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant, credential string
	if err = tx.QueryRow(ctx, `SELECT tenant_id::text,vless_uuid::text FROM vpn_clients WHERE id=$1::uuid`, clientID).Scan(&tenant, &credential); errors.Is(err, pgx.ErrNoRows) {
		return model.VPNClientUsage{}, ErrNotFound
	} else if err != nil {
		return model.VPNClientUsage{}, err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return model.VPNClientUsage{}, ErrNotFound
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return model.VPNClientUsage{}, err
	}
	before, err := scanVPNClientUsage(tx.QueryRow(ctx, vpnClientUsageQuery, clientID))
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	if before.ResetPolicy != "MONTH" {
		return model.VPNClientUsage{}, ErrTrafficPolicyConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO vpn_client_limits(client_id,monthly_bytes,device_limit) VALUES($1::uuid,$2,$3) ON CONFLICT(client_id) DO UPDATE SET monthly_bytes=EXCLUDED.monthly_bytes,device_limit=EXCLUDED.device_limit,updated_at=now()`, clientID, monthlyBytes, deviceLimit)
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	after, err := scanVPNClientUsage(tx.QueryRow(ctx, vpnClientUsageQuery, clientID))
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	rebuilds := 0
	if before.QuotaExceeded != after.QuotaExceeded {
		rebuilds, err = rebuildClientAccessNodes(ctx, tx, clientID, credential)
		if err != nil {
			return model.VPNClientUsage{}, err
		}
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.limits_updated',$2,$3,jsonb_build_object('client_id',$4::text,'monthly_bytes',$5::bigint,'device_limit',$6::integer,'rebuild_count',$7::integer))`, tenant, actorType, actorID, clientID, monthlyBytes, deviceLimit, rebuilds)
	if err != nil {
		return model.VPNClientUsage{}, err
	}
	return after, tx.Commit(ctx)
}
