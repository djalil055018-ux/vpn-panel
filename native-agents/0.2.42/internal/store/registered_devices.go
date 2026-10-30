package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/subscriptioncompat"
)

var ErrRegisteredDeviceLimit = errors.New("registered device limit reached")
var ErrRegisteredDeviceRequired = errors.New("device identifier required")
var ErrRegisteredDevicesTooMany = errors.New("remove registered devices before lowering the limit")

type SubscriptionDeviceProof struct {
	Alias        string
	TokenID      []byte
	TokenHash    []byte
	TokenVersion int64
}

func checkDeviceSubscriptionTx(ctx context.Context, tx pgx.Tx, clientID string, proof SubscriptionDeviceProof) error {
	if proof.Alias == "" && len(proof.TokenID) == 0 {
		return ErrNotFound
	}
	if len(proof.TokenID) > 0 {
		var ok bool
		err := tx.QueryRow(ctx, `SELECT true FROM vpn_client_subscriptions s WHERE s.client_id=$1::uuid AND s.token_id=$2::bytea AND s.token_version=$3 AND s.token_hash=$4::bytea AND s.status='active' FOR SHARE OF s`, clientID, proof.TokenID, proof.TokenVersion, proof.TokenHash).Scan(&ok)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
	}
	if proof.Alias != "" {
		var ok bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bot_accounts b
   JOIN bot_subscription_aliases a ON a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id AND a.alias=$2 AND a.state='active'
   JOIN bot_profiles p ON p.tenant_id=b.tenant_id
   JOIN imported_subscription_profiles head ON head.tenant_id=b.tenant_id AND head.import_id=p.import_id
   JOIN imported_subscription_revisions r ON r.id=head.revision_id AND r.tenant_id=head.tenant_id AND r.import_id=head.import_id
   JOIN remnawave_import_heads source ON source.import_id=p.import_id
   WHERE b.client_id=$1::uuid AND b.deleted_at IS NULL AND b.source_present
    AND p.state IN ('active','paused') AND p.source_identity_reviewed AND p.activated_at IS NOT NULL
    AND head.state='active' AND head.activated_at IS NOT NULL AND head.activation_sha256 IS NOT NULL
    AND p.inventory_sha256=source.inventory_sha256 AND r.inventory_sha256=source.inventory_sha256)`, clientID, proof.Alias).Scan(&ok)
		if err != nil {
			return err
		}
		if !ok {
			native, nativeErr := nativeBotAliasClientTx(ctx, tx, proof.Alias)
			if nativeErr != nil {
				return nativeErr
			}
			if native != clientID {
				return ErrNotFound
			}
		}
	}
	return nil
}

// Use the same lock order as subscription/bot mutations. Registration, device
// removal and limit edits must serialize, including requests arriving on aliases.
func lockRegisteredClient(ctx context.Context, tx pgx.Tx, clientID string) (string, int, error) {
	var tenant string
	var limit int
	err := tx.QueryRow(ctx, `SELECT tenant_id::text FROM vpn_clients WHERE id=$1::uuid`, clientID).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, ErrNotFound
	}
	if err != nil {
		return "", 0, err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return "", 0, ErrNotFound
	}
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return "", 0, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return "", 0, err
	}
	err = tx.QueryRow(ctx, `SELECT registered_device_limit FROM vpn_clients WHERE id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, clientID, tenant).Scan(&limit)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return tenant, limit, err
}

func registeredDevicesTx(ctx context.Context, tx pgx.Tx, clientID string, limit int) (model.RegisteredDevices, error) {
	out := model.RegisteredDevices{Limit: limit, Devices: []model.RegisteredDevice{}}
	rows, err := tx.Query(ctx, `SELECT id::text,right(hwid,6),platform,os_version,device_model,created_at,updated_at FROM bot_devices WHERE client_id=$1::uuid ORDER BY created_at,id`, clientID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var d model.RegisteredDevice
		if err = rows.Scan(&d.ID, &d.IdentifierHint, &d.Platform, &d.OSVersion, &d.Model, &d.CreatedAt, &d.LastSeenAt); err != nil {
			return out, err
		}
		d.IdentifierHint = "…" + d.IdentifierHint
		out.Devices = append(out.Devices, d)
	}
	out.Count = len(out.Devices)
	return out, rows.Err()
}

func (p *Postgres) RegisteredDevices(ctx context.Context, clientID string) (model.RegisteredDevices, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.RegisteredDevices{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	_, limit, err := lockRegisteredClient(ctx, tx, clientID)
	if err != nil {
		return model.RegisteredDevices{}, err
	}
	out, err := registeredDevicesTx(ctx, tx, clientID, limit)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func (p *Postgres) SetRegisteredDeviceLimit(ctx context.Context, clientID string, limit int) (model.RegisteredDevices, error) {
	if limit < 0 || limit > 1000 {
		return model.RegisteredDevices{}, ErrTenantQuota
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.RegisteredDevices{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	tenant, _, err := lockRegisteredClient(ctx, tx, clientID)
	if err != nil {
		return model.RegisteredDevices{}, err
	}
	out, err := registeredDevicesTx(ctx, tx, clientID, limit)
	if err != nil {
		return out, err
	}
	if limit > 0 && out.Count > limit {
		return out, ErrRegisteredDevicesTooMany
	}
	_, err = tx.Exec(ctx, `UPDATE vpn_clients SET registered_device_limit=$2,updated_at=now() WHERE id=$1::uuid`, clientID, limit)
	if err != nil {
		return out, err
	}
	// Fresh installations have one limit across the owner panel and bot.
	// Imported profiles retain their separately reviewed enforcement settings.
	_, err = tx.Exec(ctx, `UPDATE bot_accounts b SET hwid_device_limit=$2,updated_at=now()
 FROM bot_profiles p WHERE b.client_id=$1::uuid AND b.tenant_id=p.tenant_id
 AND p.profile_kind='native' AND b.source_present AND b.deleted_at IS NULL`, clientID, limit)
	if err != nil {
		return out, err
	}
	actor, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.device_limit_updated',$2,$3,jsonb_build_object('client_id',$4::text,'limit',$5::integer))`, tenant, actor, actorID, clientID, limit)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func (p *Postgres) DeleteRegisteredDevice(ctx context.Context, clientID, deviceID string) (model.RegisteredDevices, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.RegisteredDevices{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	tenant, limit, err := lockRegisteredClient(ctx, tx, clientID)
	if err != nil {
		return model.RegisteredDevices{}, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM bot_devices WHERE client_id=$1::uuid AND id=$2::uuid`, clientID, deviceID)
	if err != nil {
		return model.RegisteredDevices{}, err
	}
	if tag.RowsAffected() != 1 {
		return model.RegisteredDevices{}, ErrNotFound
	}
	actor, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_client.device_removed',$2,$3,jsonb_build_object('client_id',$4::text,'device_id',$5::text))`, tenant, actor, actorID, clientID, deviceID)
	if err != nil {
		return model.RegisteredDevices{}, err
	}
	out, err := registeredDevicesTx(ctx, tx, clientID, limit)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

// The caller resolves the public subscription before invoking this method.
// Browser metadata uses inspectOnly and never registers a device or returns VPN
// credentials. HEAD requests also never create bindings.
func (p *Postgres) AdmitSubscriptionDevice(ctx context.Context, clientID string, proof SubscriptionDeviceProof, device *subscriptioncompat.DeviceObservation, inspectOnly bool) (int, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	tenant, limit, err := lockRegisteredClient(ctx, tx, clientID)
	if err != nil {
		return 0, err
	}
	if err = checkDeviceSubscriptionTx(ctx, tx, clientID, proof); err != nil {
		return limit, err
	}
	if inspectOnly {
		return limit, tx.Commit(ctx)
	}
	if device == nil || device.Validate() != nil {
		if limit > 0 {
			return limit, ErrRegisteredDeviceRequired
		}
		return limit, tx.Commit(ctx)
	}
	var exists bool
	var count int
	var eligible bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bot_devices WHERE client_id=$1::uuid AND hwid=$2),(SELECT count(*) FROM bot_devices WHERE client_id=$1::uuid),status='active' AND NOT remnawave_hold AND (expires_at IS NULL OR expires_at>now()) AND NOT vpn_client_quota_exceeded(id) FROM vpn_clients WHERE id=$1::uuid`, clientID, device.HWID).Scan(&exists, &count, &eligible)
	if err != nil {
		return limit, err
	}
	if !eligible {
		return limit, ErrNotFound
	}
	if !exists && limit > 0 && count >= limit {
		return limit, ErrRegisteredDeviceLimit
	}
	// Bound optional history on unlimited subscriptions; never turn a history cap
	// into an undisclosed access restriction.
	if !exists && limit == 0 && count >= 1000 {
		return limit, tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, `INSERT INTO bot_devices(tenant_id,client_id,hwid,platform,os_version,device_model,created_at,updated_at) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,now(),now()) ON CONFLICT(client_id,hwid) DO UPDATE SET platform=COALESCE(excluded.platform,bot_devices.platform),os_version=COALESCE(excluded.os_version,bot_devices.os_version),device_model=COALESCE(excluded.device_model,bot_devices.device_model),updated_at=now()`, tenant, clientID, device.HWID, device.Platform, device.OSVersion, device.Model)
	if err != nil {
		return limit, err
	}
	return limit, tx.Commit(ctx)
}
