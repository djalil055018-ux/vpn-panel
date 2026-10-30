package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

// CustomerNativeDevices is restricted to one still-valid subscription proof.
// Rotations and removals serialize with registration and are durably replayable.
func (p *Postgres) CustomerNativeDevices(ctx context.Context, proof SubscriptionDeviceProof, action, deviceID, key, replacement string, replacementHash []byte) (botResult, error) {
	principal, ok := TenantPrincipal(ctx)
	if !ok || principal.Role != "operator" {
		return botResult{}, ErrNotFound
	}
	if len(proof.TokenID) == 0 || proof.Alias != "" {
		return botResult{}, ErrBotBridgeRequest
	}
	switch action {
	case "list", "remove-all":
		if deviceID != "" {
			return botResult{}, ErrBotBridgeRequest
		}
	case "remove":
		if !botSquadUUID.MatchString(deviceID) {
			return botResult{}, ErrBotBridgeRequest
		}
	case "rotate":
		if deviceID != "" || len(replacement) != 75 || len(replacementHash) != 32 {
			return botResult{}, ErrBotBridgeRequest
		}
	default:
		return botResult{}, ErrBotBridgeRequest
	}
	perform := func(tx pgx.Tx, tenant string) (botResult, error) {
		id, err := subscriptionClientTx(ctx, tx, proof)
		if err != nil {
			return botResult{}, err
		}
		var limit int
		err = tx.QueryRow(ctx, `SELECT c.registered_device_limit FROM vpn_clients c
 WHERE c.id=$1::uuid AND c.tenant_id=$2::uuid AND NOT c.remnawave_hold
 AND NOT EXISTS(SELECT 1 FROM bot_accounts b WHERE b.client_id=c.id AND b.source_present AND b.deleted_at IS NULL)
 FOR UPDATE OF c`, id, tenant).Scan(&limit)
		if errors.Is(err, pgx.ErrNoRows) {
			return botResult{}, ErrNotFound
		}
		if err != nil {
			return botResult{}, err
		}
		if action == "remove" || action == "remove-all" || action == "rotate" {
			// An already-removed id is an idempotent no-op; no other client's row is touched.
			_, err = tx.Exec(ctx, `DELETE FROM bot_devices WHERE client_id=$1::uuid AND ($2::text='' OR id::text=$2)`, id, deviceID)
			if err != nil {
				return botResult{}, err
			}
		}
		if action == "rotate" {
			tag, e := tx.Exec(ctx, `UPDATE vpn_client_subscriptions SET token_version=token_version+1,token_hash=$2::bytea,token_prefix=$3,rotated_at=now()
 WHERE client_id=$1::uuid AND status='active' AND token_id=$4::bytea AND token_version=$5 AND token_hash=$6::bytea`, id, replacementHash, replacement[:12], proof.TokenID, proof.TokenVersion, proof.TokenHash)
			if e != nil {
				return botResult{}, e
			}
			if tag.RowsAffected() != 1 {
				return botResult{}, ErrBotBridgeConflict
			}
		}
		if action != "list" {
			actor, actorID := accessActor(ctx)
			_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload)
 VALUES($1::uuid,'customer.subscription_devices',$2,$3,jsonb_build_object('client_id',$4::text,'action',$5::text))`, tenant, actor, actorID, id, action)
			if err != nil {
				return botResult{}, err
			}
		}
		devices, err := registeredDevicesTx(ctx, tx, id, limit)
		if err != nil {
			return botResult{}, err
		}
		result := map[string]any{"devices": devices.Devices, "limit": devices.Limit}
		if action == "rotate" {
			result["subscription_token"] = replacement
		}
		return botResponse(result)
	}
	if action == "list" {
		tx, err := p.Pool.Begin(ctx)
		if err != nil {
			return botResult{}, err
		}
		defer tx.Rollback(context.WithoutCancel(ctx))
		if err = lockTenantResource(ctx, tx, principal.TenantID); err != nil {
			return botResult{}, err
		}
		if err = lockTenantAccess(ctx, tx, principal.TenantID); err != nil {
			return botResult{}, err
		}
		result, err := perform(tx, principal.TenantID)
		if err != nil {
			return botResult{}, err
		}
		return result, tx.Commit(ctx)
	}
	fp, err := botFingerprint("POST", "/customer-devices", struct {
		Proof            SubscriptionDeviceProof
		Action, DeviceID string
	}{proof, action, deviceID})
	if err != nil {
		return botResult{}, err
	}
	return p.runBotOperation(ctx, key, fp, perform)
}

// CustomerNativeDeviceLimit is a billing-only mutation. The trusted commerce
// service calls it after a verified payment, and the operation can increase a
// native subscription by exactly one slot. The payment operation key makes a
// retry safe after either side times out.
func (p *Postgres) CustomerNativeDeviceLimit(ctx context.Context, clientID string, oldLimit, newLimit int, key string) (botResult, error) {
	principal, ok := TenantPrincipal(ctx)
	if !ok || principal.Role != "operator" {
		return botResult{}, ErrNotFound
	}
	if !botSquadUUID.MatchString(clientID) || oldLimit < 1 || newLimit != oldLimit+1 {
		return botResult{}, ErrBotBridgeRequest
	}
	fingerprint, err := botFingerprint("POST", "/customer-device-limit", struct {
		ClientID string
		OldLimit int
		NewLimit int
	}{clientID, oldLimit, newLimit})
	if err != nil {
		return botResult{}, err
	}
	return p.runBotOperation(ctx, key, fingerprint, func(tx pgx.Tx, tenant string) (botResult, error) {
		var current int
		err := tx.QueryRow(ctx, `SELECT c.registered_device_limit FROM vpn_clients c
 WHERE c.id=$1::uuid AND c.tenant_id=$2::uuid AND NOT c.remnawave_hold
 AND NOT EXISTS(SELECT 1 FROM bot_accounts b WHERE b.client_id=c.id AND b.tenant_id=c.tenant_id
  AND b.source_present AND b.deleted_at IS NULL)
 FOR UPDATE OF c`, clientID, tenant).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) {
			return botResult{}, ErrNotFound
		}
		if err != nil {
			return botResult{}, err
		}
		if current == newLimit {
			return botResponse(map[string]any{"limit": newLimit, "previous_limit": oldLimit})
		}
		if current != oldLimit {
			return botResult{}, ErrBotBridgeConflict
		}
		_, err = tx.Exec(ctx, `UPDATE vpn_clients SET registered_device_limit=$2,updated_at=now()
 WHERE id=$1::uuid AND tenant_id=$3::uuid`, clientID, newLimit, tenant)
		if err != nil {
			return botResult{}, err
		}
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload)
 VALUES($1::uuid,'customer.native_device_limit_raised',$2,$3,
  jsonb_build_object('client_id',$4::text,'previous_limit',$5::integer,'limit',$6::integer))`,
			tenant, actor, actorID, clientID, oldLimit, newLimit)
		if err != nil {
			return botResult{}, err
		}
		return botResponse(map[string]any{"limit": newLimit, "previous_limit": oldLimit})
	})
}
