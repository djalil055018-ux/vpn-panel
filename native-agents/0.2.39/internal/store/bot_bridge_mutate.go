package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/security"
)

type botLockedClient struct {
	ID, Name, Credential string
	Eligible             bool
}

func botLockClient(ctx context.Context, tx pgx.Tx, tenant string, id int64) (out botLockedClient, err error) {
	err = tx.QueryRow(ctx, `SELECT c.id::text,c.name,c.vless_uuid::text,c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now()) AND NOT vpn_client_quota_exceeded(c.id)
 FROM bot_accounts b JOIN vpn_clients c ON c.id=b.client_id AND c.tenant_id=b.tenant_id JOIN vpn_client_continuous_quotas q ON q.client_id=c.id
 WHERE b.tenant_id=$1::uuid AND b.legacy_id=$2 AND b.source_present AND b.deleted_at IS NULL AND NOT c.remnawave_hold FOR UPDATE OF b,c`, tenant, id).Scan(&out.ID, &out.Name, &out.Credential, &out.Eligible)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}
func botResponse(body any) (botResult, error) {
	raw, err := json.Marshal(map[string]any{"response": body})
	return botResult{Status: 200, Body: raw}, err
}
func (p *Postgres) BotUserAction(ctx context.Context, id int64, action, key string, days int) (botResult, error) {
	if id < 1 || id > 9007199254740991 {
		return botResult{}, ErrBotBridgeRequest
	}
	switch action {
	case "extend":
		if days < 1 || days > 3650 {
			return botResult{}, ErrBotBridgeRequest
		}
	case "enable", "disable", "reset-traffic", "delete", "revoke":
		if days != 0 {
			return botResult{}, ErrBotBridgeRequest
		}
	default:
		return botResult{}, ErrBotBridgeRequest
	}
	method, path := "POST", "/users/"+strconv.FormatInt(id, 10)+"/actions/"+action
	if action == "delete" {
		method, path = "DELETE", "/users/"+strconv.FormatInt(id, 10)
	}
	fp, err := botFingerprint(method, path, struct{ Days int }{days})
	if err != nil {
		return botResult{}, err
	}
	return p.runBotMutation(ctx, key, fp, action == "extend" || action == "reset-traffic" || action == "revoke", func(tx pgx.Tx, tenant string) (botResult, error) {
		client, err := botLockClient(ctx, tx, tenant, id)
		if err != nil {
			return botResult{}, err
		}
		if action == "delete" {
			_, err := deleteVPNClientTx(ctx, tx, client.ID, client.Name)
			if err != nil {
				return botResult{}, err
			}
			return botResponse(map[string]any{"id": id, "isDeleted": true})
		}
		rebuilds := 0
		switch action {
		case "revoke":
			before, e := clientAccessNodes(ctx, tx, client.ID, client.Credential)
			if e != nil {
				return botResult{}, e
			}
			alias, e := security.NewToken(24)
			if e != nil {
				return botResult{}, e
			}
			if _, err = tx.Exec(ctx, `UPDATE bot_subscription_aliases SET state='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE tenant_id=$1::uuid AND legacy_id=$2`, tenant, id); err != nil {
				return botResult{}, err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO bot_subscription_aliases(alias,tenant_id,legacy_id) VALUES($1,$2::uuid,$3)`, alias, tenant, id); err != nil {
				return botResult{}, err
			}
			// The credential UUID is also the epoch used by native Shadowsocks,
			// WireGuard, OpenVPN and PPTP key material. Rebuilding generates replacements
			// and removes old keys/certificates from effective runtime configuration.
			err = tx.QueryRow(ctx, `UPDATE vpn_clients SET vless_uuid=gen_random_uuid(),updated_at=now() WHERE id=$1::uuid RETURNING vless_uuid::text`, client.ID).Scan(&client.Credential)
			if err != nil {
				return botResult{}, err
			}
			if _, err = tx.Exec(ctx, `UPDATE vpn_client_subscriptions SET status='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE client_id=$1::uuid AND status='active'`, client.ID); err != nil {
				return botResult{}, err
			}
			rebuilds, err = botRebuildChangedAccess(ctx, tx, client, before)
		case "extend":
			_, err = tx.Exec(ctx, `UPDATE vpn_clients SET expires_at=GREATEST(expires_at,now())+make_interval(days=>$2),updated_at=now() WHERE id=$1::uuid`, client.ID, days)
		case "enable", "disable":
			status := "active"
			if action == "disable" {
				status = "disabled"
			}
			_, err = tx.Exec(ctx, `UPDATE vpn_clients SET status=$2,updated_at=now() WHERE id=$1::uuid AND status<>$2`, client.ID, status)
		case "reset-traffic":
			// The accounting lock precedes cursor locks in traffic delivery. The shared
			// tenant access lock already serializes this reset against incoming samples.
			// Preserve lifetime totals and every node epoch/sequence/cumulative cursor.
			_, err = tx.Exec(ctx, `UPDATE bot_accounts b SET lifetime_offset_bytes=LEAST(9000000000000000::bigint,b.lifetime_offset_bytes+q.uplink_bytes+q.downlink_bytes),updated_at=now()
   FROM vpn_client_continuous_quotas q WHERE b.client_id=q.client_id AND b.client_id=$1::uuid`, client.ID)
			if err == nil {
				_, err = tx.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET baseline_bytes=0,baseline_at=now(),uplink_bytes=0,downlink_bytes=0,updated_at=now() WHERE client_id=$1::uuid`, client.ID)
			}
		}
		if err != nil {
			return botResult{}, err
		}
		var eligible bool
		err = tx.QueryRow(ctx, `SELECT status='active' AND (expires_at IS NULL OR expires_at>now()) AND NOT vpn_client_quota_exceeded(id) FROM vpn_clients WHERE id=$1::uuid`, client.ID).Scan(&eligible)
		if err != nil {
			return botResult{}, err
		}
		if action != "revoke" && eligible != client.Eligible {
			rebuilds, err = rebuildClientAccessNodes(ctx, tx, client.ID, client.Credential)
			if err != nil {
				return botResult{}, err
			}
		}
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2,$3,$4,jsonb_build_object('client_id',$5::text,'numeric_id',$6::bigint,'days',$7::integer,'rebuild_count',$8::integer))`, tenant, "bot_bridge."+action, actor, actorID, client.ID, id, days, rebuilds)
		if err != nil {
			return botResult{}, err
		}
		raw, err := botUserTx(ctx, tx, tenant, id)
		if err != nil {
			return botResult{}, err
		}
		return botResponse(raw)
	})
}
func (p *Postgres) BotDeleteDevices(ctx context.Context, id int64, hwid *string, key string) (botResult, error) {
	if id < 1 || id > 9007199254740991 || hwid != nil && (len(*hwid) == 0 || len(*hwid) > 512 || !utf8.ValidString(*hwid) || strings.ContainsAny(*hwid, "\x00\x7f")) {
		return botResult{}, ErrBotBridgeRequest
	}
	path := "/hwid/devices/delete-all"
	if hwid != nil {
		path = "/hwid/devices/delete"
	}
	fp, err := botFingerprint("POST", path, struct {
		UserID int64
		HWID   *string
	}{id, hwid})
	if err != nil {
		return botResult{}, err
	}
	return p.runBotMutation(ctx, key, fp, false, func(tx pgx.Tx, tenant string) (botResult, error) {
		client, err := botLockClient(ctx, tx, tenant, id)
		if err != nil {
			return botResult{}, err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM bot_devices WHERE tenant_id=$1::uuid AND legacy_id=$2 AND ($3::text IS NULL OR hwid=$3)`, tenant, id, hwid)
		if err != nil {
			return botResult{}, err
		}
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'bot_bridge.devices_deleted',$2,$3,jsonb_build_object('client_id',$4::text,'count',$5::bigint))`, tenant, actor, actorID, client.ID, tag.RowsAffected())
		if err != nil {
			return botResult{}, err
		}
		return botResponse(map[string]any{"deleted": tag.RowsAffected()})
	})
}
