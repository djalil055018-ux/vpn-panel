package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/botbridge"
)

var ErrBotBridgeHeld = errors.New("bot integration is not active")
var ErrBotBridgeConflict = errors.New("bot identity or operation conflicts with current state")
var ErrBotBridgeRequest = errors.New("invalid bot operation")

type BotPreparation struct {
	TenantID        string `json:"tenant_id"`
	ImportID        string `json:"import_id"`
	InventorySHA256 string `json:"inventory_sha256"`
	Users           int    `json:"users"`
	Squads          int    `json:"squads"`
	Devices         int    `json:"devices"`
	Deleted         int    `json:"deleted"`
	MigrationReady  bool   `json:"migration_ready"`
}

// PrepareBotBridge projects the exact current, reviewed private revision. It
// creates no native grants, credentials, node generations or public subscriptions.
// Refresh is allowed only while every mapped account and the profile remain held.
func (p *Postgres) PrepareBotBridge(ctx context.Context, tenant, importID, reviewedSHA string) (out BotPreparation, err error) {
	out.TenantID = tenant
	out.ImportID = importID
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	defer func() {
		var e *pgconn.PgError
		if errors.As(err, &e) && (e.Code == "23505" || e.Code == "23503") {
			err = ErrBotBridgeConflict
		}
	}()
	var origin string
	err = tx.QueryRow(ctx, `SELECT source_origin FROM remnawave_imports WHERE id=$1::uuid AND tenant_id=$2::uuid AND state='held'`, importID, tenant).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
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
	var raw []byte
	var digest string
	err = tx.QueryRow(ctx, `SELECT r.inventory,h.inventory_sha256 FROM `+remnawaveCurrentFrom+` WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid AND i.state='held' FOR UPDATE OF h`, importID, tenant).Scan(&raw, &digest)
	if err != nil {
		return out, err
	}
	if digest != reviewedSHA {
		return out, ErrRemnawaveReview
	}
	inv, err := botbridge.ParseMetadata(raw)
	if err != nil {
		return out, err
	}
	if inv.SHA256 != digest {
		return out, ErrRemnawaveConflict
	}
	out.InventorySHA256 = digest
	var profileImport, state string
	err = tx.QueryRow(ctx, `SELECT COALESCE(import_id::text,''),state FROM bot_profiles WHERE tenant_id=$1::uuid FOR UPDATE`, tenant).Scan(&profileImport, &state)
	if err == nil && (profileImport != importID || state != "held") {
		return out, ErrBotBridgeConflict
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	var changed bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remnawave_import_clients m JOIN vpn_clients c ON c.id=m.client_id WHERE m.import_id=$1::uuid AND (c.tenant_id<>$2::uuid OR NOT c.remnawave_hold OR c.status<>'disabled' OR EXISTS(SELECT 1 FROM node_client_traffic_cursors x WHERE x.client_id=c.id)))`, importID, tenant).Scan(&changed)
	if err != nil {
		return out, err
	}
	if changed {
		return out, ErrBotBridgeConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO bot_profiles(tenant_id,import_id,inventory_sha256,subscription_base) VALUES($1::uuid,$2::uuid,$3,$4)
 ON CONFLICT(tenant_id) DO UPDATE SET inventory_sha256=excluded.inventory_sha256,subscription_base=excluded.subscription_base,prepared_at=now(),source_identity_reviewed=false`, tenant, importID, digest, inv.SubscriptionBase)
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `UPDATE bot_squads SET source_present=false WHERE tenant_id=$1::uuid`, tenant); err != nil {
		return out, err
	}
	for _, s := range inv.Squads {
		_, err = tx.Exec(ctx, `INSERT INTO bot_squads(tenant_id,source_uuid,name) VALUES($1::uuid,$2::uuid,$3) ON CONFLICT(tenant_id,source_uuid) DO UPDATE SET name=excluded.name,source_present=true`, tenant, s.UUID, s.Name)
		if err != nil {
			return out, err
		}
		out.Squads++
	}
	if _, err = tx.Exec(ctx, `UPDATE bot_accounts SET source_present=false WHERE tenant_id=$1::uuid`, tenant); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM bot_devices WHERE tenant_id=$1::uuid`, tenant); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM bot_account_squads WHERE tenant_id=$1::uuid`, tenant); err != nil {
		return out, err
	}
	live := map[int64]bool{}
	for _, u := range inv.Users {
		if u.ID >= 4503599627370496 {
			return out, ErrBotBridgeConflict
		}
		var client, deletedClient *string
		var deleted bool
		err = tx.QueryRow(ctx, `SELECT client_id::text,deleted_client_id::text,deleted_at IS NOT NULL FROM remnawave_import_clients WHERE import_id=$1::uuid AND source_user_id=$2 AND source_present`, importID, u.ID).Scan(&client, &deletedClient, &deleted)
		if err != nil {
			return out, ErrRemnawaveConflict
		}
		if client == nil && deleted && deletedClient != nil {
			out.Deleted++
			continue
		}
		if client == nil || deleted {
			return out, ErrRemnawaveConflict
		}
		var oldClient *string
		err = tx.QueryRow(ctx, `SELECT client_id::text FROM bot_accounts WHERE tenant_id=$1::uuid AND legacy_id=$2`, tenant, u.ID).Scan(&oldClient)
		if err == nil && (oldClient == nil || *oldClient != *client) {
			return out, ErrBotBridgeConflict
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO bot_accounts(tenant_id,legacy_id,client_id,username,telegram_id,email,description,hwid_device_limit,lifetime_offset_bytes,source_created_at)
  VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,legacy_id) DO UPDATE SET username=excluded.username,telegram_id=excluded.telegram_id,email=excluded.email,description=excluded.description,hwid_device_limit=excluded.hwid_device_limit,lifetime_offset_bytes=excluded.lifetime_offset_bytes,source_created_at=excluded.source_created_at,source_present=true,updated_at=now()`, tenant, u.ID, *client, u.Username, u.TelegramID, u.Email, u.Description, u.HWIDDeviceLimit, u.LifetimeBytes, u.CreatedAt)
		if err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, `UPDATE bot_subscription_aliases SET state='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1::uuid AND legacy_id=$2 AND alias<>$3`, tenant, u.ID, u.ShortUUID); err != nil {
			return out, err
		}
		var owner string
		var ownerID int64
		var aliasState string
		err = tx.QueryRow(ctx, `SELECT tenant_id::text,legacy_id,state FROM bot_subscription_aliases WHERE alias=$1`, u.ShortUUID).Scan(&owner, &ownerID, &aliasState)
		if err == nil && (owner != tenant || ownerID != u.ID || aliasState != "active") {
			return out, ErrBotBridgeConflict
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = tx.Exec(ctx, `INSERT INTO bot_subscription_aliases(alias,tenant_id,legacy_id) VALUES($1,$2::uuid,$3)`, u.ShortUUID, tenant, u.ID)
			if err != nil {
				return out, err
			}
		}
		for _, s := range u.SquadIDs {
			if _, err = tx.Exec(ctx, `INSERT INTO bot_account_squads(tenant_id,legacy_id,source_uuid) VALUES($1::uuid,$2,$3::uuid)`, tenant, u.ID, s); err != nil {
				return out, err
			}
		}
		live[u.ID] = true
		out.Users++
	}
	// Source-absent identities stay reserved. Their old aliases cannot resolve.
	if _, err = tx.Exec(ctx, `UPDATE bot_subscription_aliases a SET state='revoked',revoked_at=COALESCE(a.revoked_at,now()) FROM bot_accounts b WHERE b.tenant_id=$1::uuid AND NOT b.source_present AND a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id`, tenant); err != nil {
		return out, err
	}
	for _, d := range inv.Devices {
		if !live[d.UserID] {
			continue
		}
		_, err = tx.Exec(ctx, `INSERT INTO bot_devices(tenant_id,legacy_id,hwid,platform,os_version,device_model,created_at,updated_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8)`, tenant, d.UserID, d.HWID, d.Platform, d.OSVersion, d.Model, d.CreatedAt, d.UpdatedAt)
		if err != nil {
			return out, err
		}
		out.Devices++
	}
	actor, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'bot_bridge.prepared',$2,$3,jsonb_build_object('import_id',$4::text,'inventory_sha256',$5::text,'users',$6::integer,'devices',$7::integer,'state','held'))`, tenant, actor, actorID, importID, digest, out.Users, out.Devices)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
