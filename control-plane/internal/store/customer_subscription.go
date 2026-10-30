package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// CustomerSubscriptionContext is an internal commerce reference, never a public
// account login. A link for one subscription cannot authenticate its Telegram
// owner or reveal their other subscriptions, payments or personal information.
type CustomerSubscriptionContext struct {
	ClientID string                 `json:"client_id"`
	BotID    *int64                 `json:"bot_id"`
	Info     PublicSubscriptionInfo `json:"info"`
}

func (p *Postgres) ResolveCustomerSubscription(ctx context.Context, proof SubscriptionDeviceProof) (out CustomerSubscriptionContext, err error) {
	principal, ok := TenantPrincipal(ctx)
	if !ok || principal.Role != "operator" {
		return out, ErrNotFound
	}
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	id, err := subscriptionClientTx(ctx, tx, proof)
	if err != nil {
		return out, err
	}
	err = tx.QueryRow(ctx, `SELECT c.id::text,b.legacy_id FROM vpn_clients c
 LEFT JOIN bot_accounts b ON b.client_id=c.id AND b.tenant_id=c.tenant_id
 AND b.source_present AND b.deleted_at IS NULL
 WHERE c.id=$1::uuid AND c.tenant_id=$2::uuid AND NOT c.remnawave_hold`, id, principal.TenantID).Scan(&out.ClientID, &out.BotID)
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomerSubscriptionContext{}, ErrNotFound
	}
	if err != nil {
		return CustomerSubscriptionContext{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return CustomerSubscriptionContext{}, err
	}
	out.Info, err = p.PublicSubscriptionInfo(ctx, proof)
	if err != nil {
		return CustomerSubscriptionContext{}, err
	}
	return out, nil
}

// Native renewals keep the original client, credential, grants, devices and
// accounting policy. Payment approval happens in the trusted commerce service.
// The durable receipt and the access rebuild commit in the same transaction.
func (p *Postgres) CustomerRenewNative(ctx context.Context, clientID string, days int, key string) (botResult, error) {
	if !botSquadUUID.MatchString(clientID) || days < 1 || days > 3650 {
		return botResult{}, ErrBotBridgeRequest
	}
	fingerprint, err := botFingerprint("POST", "/customer-renew", struct {
		ClientID string
		Days     int
	}{clientID, days})
	if err != nil {
		return botResult{}, err
	}
	return p.runBotOperation(ctx, key, fingerprint, func(tx pgx.Tx, tenant string) (botResult, error) {
		var client botLockedClient
		var canRenew bool
		err := tx.QueryRow(ctx, `SELECT c.id::text,c.name,c.vless_uuid::text,
 COALESCE(c.status='active' AND c.expires_at>now() AND NOT vpn_client_quota_exceeded(c.id),false),
 c.status='active' AND c.expires_at IS NOT NULL AND NOT vpn_client_quota_exceeded(c.id)
 FROM vpn_clients c WHERE c.id=$1::uuid AND c.tenant_id=$2::uuid AND NOT c.remnawave_hold
 AND NOT EXISTS(SELECT 1 FROM bot_accounts b WHERE b.client_id=c.id AND b.source_present AND b.deleted_at IS NULL)
 FOR UPDATE OF c`, clientID, tenant).Scan(&client.ID, &client.Name, &client.Credential, &client.Eligible, &canRenew)
		if errors.Is(err, pgx.ErrNoRows) {
			return botResult{}, ErrNotFound
		}
		if err != nil {
			return botResult{}, err
		}
		if !canRenew {
			return botResult{}, ErrBotBridgeConflict
		}
		var expiry string
		err = tx.QueryRow(ctx, `UPDATE vpn_clients SET expires_at=GREATEST(expires_at,now())+make_interval(days=>$2),updated_at=now()
 WHERE id=$1::uuid RETURNING expires_at::text`, clientID, days).Scan(&expiry)
		if err != nil {
			return botResult{}, err
		}
		rebuilds := 0
		if !client.Eligible {
			rebuilds, err = rebuildClientAccessNodes(ctx, tx, client.ID, client.Credential)
			if err != nil {
				return botResult{}, err
			}
		}
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload)
 VALUES($1::uuid,'customer.subscription_renewed',$2,$3,jsonb_build_object('client_id',$4::text,'days',$5::integer,'rebuild_count',$6::integer))`, tenant, actor, actorID, client.ID, days, rebuilds)
		if err != nil {
			return botResult{}, err
		}
		return botResponse(map[string]any{"expires_at": expiry, "status": "active"})
	})
}
