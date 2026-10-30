package store

import (
	"context"
	"strconv"
	"time"
	"vpn-platform/internal/clientdirectory"
	"vpn-platform/internal/model"
)

// Enrichment uses tenant-scoped aggregate queries rather than fetching a
// credential-bearing account or subscription for every table row.
func (p *Postgres) enrichClientDirectory(ctx context.Context, tenant string, clients []model.VPNClient) error {
	index := map[string]int{}
	for i, c := range clients {
		index[c.ID] = i
	}
	if len(index) == 0 {
		return nil
	}
	rows, err := p.Pool.Query(ctx, `SELECT c.id::text,b.legacy_id,b.telegram_id,
 ARRAY(SELECT DISTINCT names.name FROM (
  SELECT p.name FROM vpn_client_access_plans m JOIN vpn_access_plans p ON p.id=m.plan_id AND p.tenant_id=m.tenant_id WHERE m.client_id=c.id AND m.tenant_id=c.tenant_id AND p.enabled
  UNION SELECT s.name FROM bot_accounts a JOIN bot_account_squads m ON m.tenant_id=a.tenant_id AND m.legacy_id=a.legacy_id JOIN bot_squads s ON s.tenant_id=m.tenant_id AND s.source_uuid=m.source_uuid WHERE a.client_id=c.id AND a.tenant_id=c.tenant_id AND s.source_present
  UNION SELECT p.name FROM billing_entitlements e JOIN vpn_access_plans p ON p.id=e.plan_id AND p.tenant_id=e.tenant_id WHERE e.client_id=c.id AND e.tenant_id=c.tenant_id AND e.expires_at>now() AND p.enabled
 ) names ORDER BY names.name),
 (SELECT n.name FROM node_client_traffic_cursors cur JOIN nodes n ON n.id=cur.node_id AND n.tenant_id=c.tenant_id WHERE cur.client_id=c.id AND cur.last_online_at IS NOT NULL ORDER BY cur.last_online_at DESC,cur.node_id LIMIT 1),
 (SELECT min(first_connected_at) FROM node_client_traffic_cursors WHERE client_id=c.id),
 (SELECT max(last_online_at) FROM node_client_traffic_cursors WHERE client_id=c.id),
 EXISTS(SELECT 1 FROM node_client_traffic_cursors WHERE client_id=c.id AND active_ips_known AND active_ips>0 AND observed_at>now()-interval '2 minutes'),
 (EXISTS(SELECT 1 FROM node_client_traffic_cursors WHERE client_id=c.id AND active_ips_known AND observed_at>now()-interval '2 minutes')
 AND NOT EXISTS(SELECT 1 FROM node_client_traffic_cursors WHERE client_id=c.id AND NOT active_ips_known AND observed_at>now()-interval '2 minutes')),
 LEAST(9000000000000000::bigint,CASE WHEN b.legacy_id IS NOT NULL THEN b.lifetime_offset_bytes+COALESCE(q.uplink_bytes,0)+COALESCE(q.downlink_bytes,0)
 ELSE COALESCE(q.baseline_bytes,0)+COALESCE((SELECT sum(uplink_bytes+downlink_bytes) FROM vpn_client_usage_monthly WHERE client_id=c.id),0) END)::bigint,
 (SELECT max(created_at) FROM audit_events WHERE tenant_id=c.tenant_id AND event_type='bot_bridge.reset-traffic' AND payload->>'client_id'=c.id::text),
 m.import_id::text,m.source_user_id
 FROM vpn_clients c LEFT JOIN bot_accounts b ON b.client_id=c.id AND b.tenant_id=c.tenant_id
 LEFT JOIN vpn_client_continuous_quotas q ON q.client_id=c.id
 LEFT JOIN remnawave_import_clients m ON m.client_id=c.id AND m.source_present
 WHERE c.tenant_id=$1::uuid`, tenant)
	if err != nil {
		return err
	}
	imports := map[string]map[int64]int{}
	for rows.Next() {
		var id string
		var numeric, telegram, sourceID *int64
		var sourceImport *string
		var first, last, reset *time.Time
		var online, observed bool
		var lifetime int64
		metadata := model.ClientDirectory{Groups: []string{}, ConnectionState: "unknown"}
		if err = rows.Scan(&id, &numeric, &telegram, &metadata.Groups, &metadata.LastNodeName, &first, &last, &online, &observed, &lifetime, &reset, &sourceImport, &sourceID); err != nil {
			rows.Close()
			return err
		}
		i, found := index[id]
		if !found {
			continue
		}
		metadata.NumericID = numeric
		metadata.LifetimeUsedBytes = &lifetime
		if telegram != nil {
			text := strconv.FormatInt(*telegram, 10)
			metadata.TelegramID = &text
		}
		if first != nil {
			metadata.FirstConnectedAt = &model.DirectoryTime{Value: first}
		}
		if last != nil {
			metadata.LastOnlineAt = &model.DirectoryTime{Value: last}
		}
		if reset != nil {
			metadata.LastTrafficResetAt = &model.DirectoryTime{Value: reset}
		}
		if online {
			metadata.ConnectionState = "online"
		} else if observed && last != nil {
			metadata.ConnectionState = "offline"
		}
		clients[i].Directory = &metadata
		if sourceImport != nil && sourceID != nil {
			if imports[*sourceImport] == nil {
				imports[*sourceImport] = map[int64]int{}
			}
			imports[*sourceImport][*sourceID] = i
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(imports) == 0 {
		return nil
	}
	ids := make([]string, 0, len(imports))
	for id := range imports {
		ids = append(ids, id)
	}
	snapshots, err := p.Pool.Query(ctx, `SELECT i.id::text,r.inventory,h.inventory_sha256 FROM remnawave_imports i JOIN remnawave_import_heads h ON h.import_id=i.id JOIN remnawave_inventory_revisions r ON r.import_id=h.import_id AND r.inventory_sha256=h.inventory_sha256 WHERE i.tenant_id=$1::uuid AND i.id=ANY($2::uuid[])`, tenant, ids)
	if err != nil {
		return err
	}
	defer snapshots.Close()
	for snapshots.Next() {
		var id, digest string
		var raw []byte
		if err = snapshots.Scan(&id, &raw, &digest); err != nil {
			return err
		}
		projected, e := clientdirectory.ProjectSnapshot(raw, digest)
		if e != nil {
			return e
		}
		for sourceID, i := range imports[id] {
			source, ok := projected[sourceID]
			if !ok {
				continue
			}
			if clients[i].RemnawaveHold {
				clients[i].Directory = &source
				continue
			}
			// After cutover the current counters and groups remain authoritative; only
			// historical observations and source-only tags fill their missing values.
			current := clients[i].Directory
			current.Tag = source.Tag
			if current.NumericID == nil {
				current.NumericID = source.NumericID
			}
			if current.TelegramID == nil {
				current.TelegramID = source.TelegramID
			}
			if source.FirstConnectedAt != nil && source.FirstConnectedAt.Value != nil && (current.FirstConnectedAt == nil || current.FirstConnectedAt.Value == nil || source.FirstConnectedAt.Value.Before(*current.FirstConnectedAt.Value)) {
				current.FirstConnectedAt = source.FirstConnectedAt
			}
			if current.LastOnlineAt == nil || (source.LastOnlineAt != nil && source.LastOnlineAt.Value != nil && (current.LastOnlineAt.Value == nil || source.LastOnlineAt.Value.After(*current.LastOnlineAt.Value))) {
				current.LastOnlineAt = source.LastOnlineAt
				current.LastNodeName = source.LastNodeName
			}
			if current.LastTrafficResetAt == nil || (source.LastTrafficResetAt != nil && source.LastTrafficResetAt.Value != nil && (current.LastTrafficResetAt.Value == nil || source.LastTrafficResetAt.Value.After(*current.LastTrafficResetAt.Value))) {
				current.LastTrafficResetAt = source.LastTrafficResetAt
			}
		}
	}
	return snapshots.Err()
}
