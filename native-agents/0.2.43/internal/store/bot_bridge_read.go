package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

type BotStatus struct {
	ContractVersion int      `json:"contract_version"`
	TenantID        string   `json:"tenant_id"`
	State           string   `json:"state"`
	MigrationReady  bool     `json:"migration_ready"`
	Capabilities    []string `json:"capabilities"`
}

// Capabilities become available only after committed runtime/public cutover.
// This is persistent migration readiness, not an all-nodes-online health check:
// a later node outage must not prevent the bot from managing existing accounts.
func (p *Postgres) BotBridgeStatus(ctx context.Context) (out BotStatus, err error) {
	tenant, err := botTenant(ctx)
	if err != nil {
		return out, err
	}
	out = BotStatus{ContractVersion: 1, TenantID: tenant, State: "unconfigured", Capabilities: []string{"numeric_identity_v1", "users_read_v1", "devices_read_v1"}}
	err = p.Pool.QueryRow(ctx, `SELECT b.state,COALESCE(
 b.state='active' AND b.source_identity_reviewed AND b.activated_at IS NOT NULL
 AND (b.profile_kind='native' OR (b.profile_kind='imported' AND c.state='active' AND c.verified_at IS NOT NULL AND i.state='active'
 AND b.inventory_sha256=h.inventory_sha256 AND c.inventory_sha256=h.inventory_sha256
 AND s.state='active' AND s.import_id=b.import_id AND s.revision_id=c.subscription_revision_id
 AND s.activation_sha256=c.publication_sha256)),false)
 FROM bot_profiles b
 LEFT JOIN remnawave_imports i ON i.id=b.import_id AND i.tenant_id=b.tenant_id
 LEFT JOIN remnawave_import_heads h ON h.import_id=b.import_id
 LEFT JOIN remnawave_cutovers c ON c.import_id=b.import_id AND c.tenant_id=b.tenant_id
 LEFT JOIN imported_subscription_profiles s ON s.tenant_id=b.tenant_id
 WHERE b.tenant_id=$1::uuid`, tenant).Scan(&out.State, &out.MigrationReady)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err == nil && out.MigrationReady {
		out.Capabilities = []string{"numeric_identity_v1", "users_v1", "no_reset_quota_v1", "squad_grants_v1", "subscription_v1", "devices_v1", "nodes_v1", "durable_operations_v1", "customer_state_v1"}
	}
	return out, err
}

type BotUserFilter struct {
	After      int64
	Size       int
	TelegramID *int64
	Username   *string
	Email      *string
}
type BotUserPage struct {
	Users      []json.RawMessage `json:"users"`
	NextCursor *int64            `json:"nextCursor"`
}

func botReadActive(ctx context.Context, tx pgx.Tx, tenant string) error {
	var active bool
	err := tx.QueryRow(ctx, `SELECT COALESCE(b.state='active' AND b.source_identity_reviewed AND b.activated_at IS NOT NULL AND (b.profile_kind='native' OR (b.profile_kind='imported' AND b.inventory_sha256=h.inventory_sha256)),false)
 FROM bot_profiles b LEFT JOIN remnawave_import_heads h ON h.import_id=b.import_id WHERE b.tenant_id=$1::uuid`, tenant).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrBotBridgeHeld
	}
	if err != nil {
		return err
	}
	if !active {
		return ErrBotBridgeHeld
	}
	return nil
}

const botUserJSON = `jsonb_build_object(
 'id',b.legacy_id,'username',b.username,
 'status',CASE WHEN c.status='disabled' THEN 'DISABLED' WHEN c.expires_at<=now() THEN 'EXPIRED' WHEN vpn_client_quota_exceeded(c.id) THEN 'LIMITED' ELSE 'ACTIVE' END,
 'expireAt',c.expires_at,'createdAt',b.source_created_at,'updatedAt',GREATEST(b.updated_at,c.updated_at),
 'telegramId',b.telegram_id,'email',b.email,'description',b.description,'hwidDeviceLimit',b.hwid_device_limit,
 'shortUuid',a.alias,'subscriptionUrl',p.subscription_base||a.alias,'trafficLimitStrategy','NO_RESET','trafficLimitBytes',q.limit_bytes,
 'usedTrafficBytes',q.baseline_bytes+q.uplink_bytes+q.downlink_bytes,
 'userTraffic',jsonb_build_object('usedTrafficBytes',q.baseline_bytes+q.uplink_bytes+q.downlink_bytes,'lifetimeUsedTrafficBytes',b.lifetime_offset_bytes+q.uplink_bytes+q.downlink_bytes),
 'activeInternalSquads',COALESCE((SELECT jsonb_agg(jsonb_build_object('uuid',s.source_uuid,'name',s.name) ORDER BY s.source_uuid)
 FROM bot_account_squads m JOIN bot_squads s ON s.tenant_id=m.tenant_id AND s.source_uuid=m.source_uuid
 WHERE m.tenant_id=b.tenant_id AND m.legacy_id=b.legacy_id AND s.source_present),'[]'::jsonb))`
const botUserFrom = `bot_accounts b JOIN vpn_clients c ON c.id=b.client_id AND c.tenant_id=b.tenant_id
 JOIN bot_profiles p ON p.tenant_id=b.tenant_id JOIN vpn_client_continuous_quotas q ON q.client_id=c.id
 JOIN bot_subscription_aliases a ON a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id AND a.state='active'`
const botUserVisible = `b.tenant_id=$1::uuid AND b.source_present AND b.deleted_at IS NULL AND NOT c.remnawave_hold`

func botUserTx(ctx context.Context, tx pgx.Tx, tenant string, id int64) (json.RawMessage, error) {
	var out json.RawMessage
	err := tx.QueryRow(ctx, `SELECT `+botUserJSON+` FROM `+botUserFrom+` WHERE `+botUserVisible+` AND b.legacy_id=$2`, tenant, id).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}
func (p *Postgres) BotUser(ctx context.Context, id int64, username *string) (json.RawMessage, error) {
	tenant, err := botTenant(ctx)
	if err != nil {
		return nil, err
	}
	if username == nil && (id < 1 || id > 9007199254740991) || username != nil && (len(*username) == 0 || len(*username) > 256) {
		return nil, ErrBotBridgeRequest
	}
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = botReadActive(ctx, tx, tenant); err != nil {
		return nil, err
	}
	if username != nil {
		err = tx.QueryRow(ctx, `SELECT legacy_id FROM bot_accounts WHERE tenant_id=$1::uuid AND username=$2 AND source_present AND deleted_at IS NULL`, tenant, *username).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
	}
	out, err := botUserTx(ctx, tx, tenant, id)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}
func (p *Postgres) BotUsers(ctx context.Context, f BotUserFilter) (out BotUserPage, err error) {
	out.Users = []json.RawMessage{}
	tenant, err := botTenant(ctx)
	if err != nil {
		return out, err
	}
	if f.After < 0 || f.After > 9007199254740991 || f.Size < 1 || f.Size > 1000 || f.TelegramID != nil && (*f.TelegramID < 0 || *f.TelegramID > 9007199254740991) || f.Username != nil && len(*f.Username) > 256 || f.Email != nil && len(*f.Email) > 320 {
		return out, ErrBotBridgeRequest
	}
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = botReadActive(ctx, tx, tenant); err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT b.legacy_id,`+botUserJSON+` FROM `+botUserFrom+` WHERE `+botUserVisible+`
 AND b.legacy_id>$2 AND ($3::bigint IS NULL OR b.telegram_id=$3)
 AND ($4::text IS NULL OR b.username=$4) AND ($5::text IS NULL OR b.email=$5)
 ORDER BY b.legacy_id LIMIT $6`, tenant, f.After, f.TelegramID, f.Username, f.Email, f.Size+1)
	if err != nil {
		return out, err
	}
	var last int64
	for rows.Next() {
		var id int64
		var user json.RawMessage
		if err = rows.Scan(&id, &user); err != nil {
			rows.Close()
			return out, err
		}
		if len(out.Users) == f.Size {
			out.NextCursor = &last
			break
		}
		out.Users = append(out.Users, user)
		last = id
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (p *Postgres) BotDevices(ctx context.Context, id int64) (json.RawMessage, error) {
	tenant, err := botTenant(ctx)
	if err != nil {
		return nil, err
	}
	if id < 1 || id > 9007199254740991 {
		return nil, ErrBotBridgeRequest
	}
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = botReadActive(ctx, tx, tenant); err != nil {
		return nil, err
	}
	if _, err = botUserTx(ctx, tx, tenant, id); err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = tx.QueryRow(ctx, `SELECT jsonb_build_object('devices',COALESCE(jsonb_agg(jsonb_build_object('userId',legacy_id,'hwid',hwid,'platform',platform,'osVersion',os_version,'deviceModel',device_model,'createdAt',created_at,'updatedAt',updated_at) ORDER BY created_at,hwid),'[]'::jsonb))
 FROM bot_devices WHERE tenant_id=$1::uuid AND legacy_id=$2`, tenant, id).Scan(&out)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (p *Postgres) BotNodes(ctx context.Context) (json.RawMessage, error) {
	tenant, err := botTenant(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = botReadActive(ctx, tx, tenant); err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = tx.QueryRow(ctx, `SELECT jsonb_build_object('nodes',COALESCE(jsonb_agg(payload ORDER BY name,id),'[]'::jsonb)) FROM (
 SELECT n.id,n.name,jsonb_build_object('uuid',n.id,'name',n.name,'isDisabled',false,
 'isConnecting',COALESCE(h.checked_at>=now()-interval '90 seconds' AND h.healthy AND (n.applied_generation<>n.desired_generation OR h.applied_generation<>n.desired_generation),false),
 'isConnected',COALESCE(h.checked_at>=now()-interval '90 seconds' AND h.healthy AND n.applied_generation=n.desired_generation AND h.applied_generation=n.desired_generation,false),
 'usersOnline',NULL,'usersOnlineKnown',false,'trafficUsedBytes',NULL,'trafficLimitBytes',NULL,'xrayUptime',NULL,
 'versions',jsonb_build_object('node',n.agent_version,'xray',CASE WHEN n.runtime_core='xray' THEN h.core_version ELSE NULL END,'core',h.core_version,'coreType',n.runtime_core),
 'lastCheckedAt',h.checked_at,'lastStatusChange',NULL,'tags','[]'::jsonb,
 'lastStatusMessage',CASE WHEN h.checked_at IS NULL OR h.checked_at<now()-interval '90 seconds' THEN 'Нет свежего отчёта агента'
 WHEN NOT h.healthy THEN 'VPN-служба сообщает об ошибке'
 WHEN n.applied_generation<>n.desired_generation OR h.applied_generation<>n.desired_generation THEN 'Применяется конфигурация'
 ELSE 'VPN-служба работает' END) payload
 FROM nodes n LEFT JOIN node_health h ON h.node_id=n.id
 WHERE n.tenant_id=$1::uuid AND EXISTS(SELECT 1 FROM bot_squads b JOIN vpn_access_plan_services ps ON ps.plan_id=b.plan_id AND ps.tenant_id=b.tenant_id
 JOIN vpn_services s ON s.id=ps.service_id AND s.tenant_id=ps.tenant_id WHERE b.tenant_id=n.tenant_id AND b.source_present AND s.node_id=n.id)
 ) visible`, tenant).Scan(&out)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}
