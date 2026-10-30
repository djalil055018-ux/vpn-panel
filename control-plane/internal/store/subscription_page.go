package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// PublicSubscriptionInfo is a deliberate allowlist. Never embed a client,
// connection, device or subscription record here: those contain credentials.
type PublicSubscriptionInfo struct {
	Name         string             `json:"name"`
	Brand        string             `json:"brand"`
	SupportURL   string             `json:"support_url"`
	SupportLabel string             `json:"support_label"`
	Status       string             `json:"status"`
	ExpiresAt    *time.Time         `json:"expires_at"`
	UsedBytes    int64              `json:"used_bytes"`
	LimitBytes   int64              `json:"limit_bytes"`
	ResetPolicy  string             `json:"reset_policy"`
	DeviceLimit  int                `json:"device_limit"`
	DeviceCount  int                `json:"device_count"`
	UpdatedAt    time.Time          `json:"updated_at"`
	AutoProfile  *PublicAutoProfile `json:"auto_profile,omitempty"`
}

// Public display settings only; tenant IDs and allocation inputs stay private.
type PublicAutoProfile struct {
	Name         string `json:"name"`
	RussiaDirect bool   `json:"russia_direct"`
}

// Browsing does not register a device, update last_access_at or grant access.
// A current signed token or imported alias can show an expired/disabled account's
// status. Rotated/revoked links cannot reveal metadata. All reads share a snapshot.
func (p *Postgres) PublicSubscriptionInfo(ctx context.Context, proof SubscriptionDeviceProof) (out PublicSubscriptionInfo, err error) {
	defer func() {
		if err != nil {
			out = PublicSubscriptionInfo{}
		}
	}()
	tx, err := p.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	clientID, err := subscriptionClientTx(ctx, tx, proof)
	if err != nil {
		return out, err
	}
	var tenantID string
	err = tx.QueryRow(ctx, `SELECT c.id::text,c.tenant_id::text,c.name,
 COALESCE(b.display_name,'PAUK'),COALESCE(b.support_url,''),COALESCE(b.support_label,''),
 CASE WHEN c.status='disabled' THEN 'disabled' WHEN c.expires_at<=now() THEN 'expired'
 WHEN vpn_client_quota_exceeded(c.id) THEN 'quota_exceeded' ELSE 'active' END,
 c.expires_at,c.registered_device_limit,(SELECT count(*)::integer FROM bot_devices d WHERE d.client_id=c.id),now()
 FROM vpn_clients c
 LEFT JOIN tenant_branding b ON b.tenant_id=c.tenant_id
 WHERE c.id=$1::uuid AND NOT c.remnawave_hold`,
		clientID).Scan(&clientID, &tenantID, &out.Name, &out.Brand, &out.SupportURL, &out.SupportLabel, &out.Status, &out.ExpiresAt, &out.DeviceLimit, &out.DeviceCount, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if !tenantScopeAllowed(ctx, tenantID) {
		return out, ErrNotFound
	}
	usage, err := scanVPNClientUsage(tx.QueryRow(ctx, vpnClientUsageQuery, clientID))
	if err != nil {
		return out, err
	}
	out.UsedBytes = usage.UsedBytes
	out.LimitBytes = usage.TrafficLimitBytes
	out.ResetPolicy = usage.ResetPolicy
	auto, err := readAutoProfileSettings(ctx, tx, tenantID)
	if err != nil {
		return out, err
	}
	if auto.Enabled {
		out.AutoProfile = &PublicAutoProfile{Name: auto.Name, RussiaDirect: auto.RussiaDirect}
	}
	return out, tx.Commit(ctx)
}

// Resolve a current subscription proof without registering a device or changing
// admission state. Callers must separately enforce their tenant/role boundary.
func subscriptionClientTx(ctx context.Context, tx pgx.Tx, proof SubscriptionDeviceProof) (string, error) {
	var clientID string
	var err error
	if proof.Alias != "" {
		if !importedAlias.MatchString(proof.Alias) || len(proof.TokenID) != 0 {
			return "", ErrNotFound
		}
		err = tx.QueryRow(ctx, `SELECT b.client_id::text FROM bot_accounts b
 JOIN bot_subscription_aliases a ON a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id
 WHERE a.alias=$1 AND a.state='active' AND b.source_present AND b.deleted_at IS NULL`, proof.Alias).Scan(&clientID)
		if err == nil {
			err = checkDeviceSubscriptionTx(ctx, tx, clientID, proof)
		}
	} else {
		err = tx.QueryRow(ctx, `SELECT s.client_id::text FROM vpn_client_subscriptions s
 JOIN vpn_clients c ON c.id=s.client_id AND c.tenant_id=s.tenant_id
 WHERE s.token_id=$1 AND s.token_version=$2 AND s.token_hash=$3 AND s.status='active'`,
			proof.TokenID, proof.TokenVersion, proof.TokenHash).Scan(&clientID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return clientID, nil
}
