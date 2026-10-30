package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/subscriptioncompat"
)

// ObserveImportedSubscriptionDevice is best-effort display history. It never
// grants VPN access or enforces a device count. Recheck the current alias under
// native mutation locks so revocation/deletion cannot resurrect old device data.
func (p *Postgres) ObserveImportedSubscriptionDevice(ctx context.Context, clientID, alias string, d subscriptioncompat.DeviceObservation) error {
	if !xrayPreparationUUID.MatchString(clientID) || !importedAlias.MatchString(alias) || d.Validate() != nil {
		return ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM bot_accounts WHERE client_id=$1::uuid AND deleted_at IS NULL`, clientID).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if principal, ok := TenantPrincipal(ctx); ok && principal.TenantID != tenant {
		return ErrNotFound
	}
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return err
	}
	var id int64
	err = tx.QueryRow(ctx, `SELECT b.legacy_id
 FROM bot_accounts b JOIN vpn_clients c ON c.id=b.client_id AND c.tenant_id=b.tenant_id
 JOIN bot_profiles p ON p.tenant_id=b.tenant_id
 JOIN bot_subscription_aliases a ON a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id AND a.alias=$2 AND a.state='active'
 JOIN imported_subscription_profiles head ON head.tenant_id=b.tenant_id AND head.import_id=p.import_id
 JOIN imported_subscription_revisions r ON r.id=head.revision_id AND r.tenant_id=head.tenant_id AND r.import_id=head.import_id
 JOIN remnawave_import_heads source ON source.import_id=p.import_id
 WHERE b.client_id=$1::uuid AND b.tenant_id=$3::uuid AND b.source_present AND b.deleted_at IS NULL AND NOT c.remnawave_hold
 AND head.state='active' AND head.activated_at IS NOT NULL AND head.activation_sha256 IS NOT NULL
 AND p.state IN ('active','paused') AND p.source_identity_reviewed AND p.activated_at IS NOT NULL
 AND p.inventory_sha256=source.inventory_sha256 AND r.inventory_sha256=source.inventory_sha256
 FOR UPDATE OF b,c`, clientID, alias, tenant).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO bot_devices(tenant_id,legacy_id,hwid,platform,os_version,device_model,created_at,updated_at)
 VALUES($1::uuid,$2,$3,$4,$5,$6,now(),now())
 ON CONFLICT(tenant_id,legacy_id,hwid) DO UPDATE SET
 platform=COALESCE(excluded.platform,bot_devices.platform),
 os_version=COALESCE(excluded.os_version,bot_devices.os_version),
 device_model=COALESCE(excluded.device_model,bot_devices.device_model),updated_at=now()`, tenant, id, d.HWID, d.Platform, d.OSVersion, d.Model)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
