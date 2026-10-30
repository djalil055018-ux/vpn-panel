package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// CustomerSubscriptionState contains only billing eligibility. Credentials,
// subscription links, customer names and personal information are never returned.
type CustomerSubscriptionState struct {
	CanRenew     bool `json:"can_renew"`
	CanAddDevice bool `json:"can_add_device"`
	DeviceLimit  int  `json:"device_limit"`
}

func (p *Postgres) CustomerSubscriptionState(ctx context.Context, clientID string) (out CustomerSubscriptionState, err error) {
	principal, ok := TenantPrincipal(ctx)
	if !ok || principal.Role != "operator" {
		return out, ErrNotFound
	}
	if !botSquadUUID.MatchString(clientID) {
		return out, ErrBotBridgeRequest
	}
	err = p.Pool.QueryRow(ctx, `SELECT
 c.status='active' AND c.expires_at IS NOT NULL AND NOT vpn_client_quota_exceeded(c.id),
 c.registered_device_limit>0,c.registered_device_limit
 FROM vpn_clients c WHERE c.id=$1::uuid AND c.tenant_id=$2::uuid AND NOT c.remnawave_hold
 AND EXISTS(SELECT 1 FROM bot_profiles p LEFT JOIN remnawave_import_heads h ON h.import_id=p.import_id
 WHERE p.tenant_id=c.tenant_id AND p.state='active' AND p.source_identity_reviewed AND p.activated_at IS NOT NULL
 AND (p.profile_kind='native' OR (p.profile_kind='imported' AND p.inventory_sha256=h.inventory_sha256)))
 AND NOT EXISTS(SELECT 1 FROM bot_accounts b WHERE b.client_id=c.id AND b.tenant_id=c.tenant_id
 AND b.source_present AND b.deleted_at IS NULL)`, clientID, principal.TenantID).Scan(&out.CanRenew, &out.CanAddDevice, &out.DeviceLimit)
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomerSubscriptionState{}, ErrNotFound
	}
	return out, err
}
