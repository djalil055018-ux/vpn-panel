package store

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/security"
)

var botUsername = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
var botSquadUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type BotCreateInput struct {
	Username             string   `json:"username"`
	DurationDays         int      `json:"durationDays"`
	TelegramID           *int64   `json:"telegramId,omitempty"`
	Description          string   `json:"description"`
	TrafficLimitBytes    int64    `json:"trafficLimitBytes"`
	TrafficLimitStrategy string   `json:"trafficLimitStrategy"`
	HWIDDeviceLimit      int      `json:"hwidDeviceLimit"`
	ActiveInternalSquads []string `json:"activeInternalSquads"`
}
type BotPatchInput struct {
	ID                   int64      `json:"id"`
	ExpireAt             *time.Time `json:"expireAt,omitempty"`
	TrafficLimitBytes    *int64     `json:"trafficLimitBytes,omitempty"`
	HWIDDeviceLimit      *int       `json:"hwidDeviceLimit,omitempty"`
	Description          *string    `json:"description,omitempty"`
	ActiveInternalSquads *[]string  `json:"activeInternalSquads,omitempty"`
}

func botText(value string, max int) bool {
	return utf8.ValidString(value) && len(value) <= max && !strings.ContainsAny(value, "\x00\x7f")
}
func botSquads(in []string, allowEmpty bool) ([]string, error) {
	if len(in) > 100 || len(in) == 0 && !allowEmpty {
		return nil, ErrBotBridgeRequest
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.ToLower(v)
		if !botSquadUUID.MatchString(v) || seen[v] {
			return nil, ErrBotBridgeRequest
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}
func botSQLError(err error) error {
	var e *pgconn.PgError
	if errors.As(err, &e) && (e.Code == "23505" || e.Code == "23503") {
		return ErrBotBridgeConflict
	}
	return err
}
func botValidateSquads(ctx context.Context, tx pgx.Tx, tenant string, groups []string) error {
	rows, err := tx.Query(ctx, `SELECT s.source_uuid::text FROM bot_squads s JOIN vpn_access_plans p ON p.id=s.plan_id AND p.tenant_id=s.tenant_id
 WHERE s.tenant_id=$1::uuid AND s.source_uuid=ANY($2::uuid[]) AND s.source_present AND p.enabled
 AND (EXISTS(SELECT 1 FROM vpn_access_plan_services ps JOIN vpn_services v ON v.id=ps.service_id AND v.tenant_id=ps.tenant_id WHERE ps.plan_id=p.id AND ps.tenant_id=p.tenant_id AND v.enabled) OR EXISTS(SELECT 1 FROM vpn_active_cascades k WHERE k.plan_id=p.id AND k.tenant_id=p.tenant_id))
 ORDER BY s.source_uuid FOR SHARE OF s,p`, tenant, groups)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count != len(groups) {
		return ErrBotBridgeConflict
	}
	return nil
}
func botSetSquads(ctx context.Context, tx pgx.Tx, tenant string, id int64, groups []string) (bool, error) {
	if err := botValidateSquads(ctx, tx, tenant, groups); err != nil {
		return false, err
	}
	var existing []string
	err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(source_uuid::text ORDER BY source_uuid),ARRAY[]::text[]) FROM bot_account_squads WHERE tenant_id=$1::uuid AND legacy_id=$2`, tenant, id).Scan(&existing)
	if err != nil {
		return false, err
	}
	same := len(existing) == len(groups)
	if same {
		for i := range groups {
			if groups[i] != existing[i] {
				same = false
				break
			}
		}
	}
	if same {
		return false, nil
	}
	if _, err = tx.Exec(ctx, `DELETE FROM bot_account_squads WHERE tenant_id=$1::uuid AND legacy_id=$2`, tenant, id); err != nil {
		return false, err
	}
	for _, group := range groups {
		if _, err = tx.Exec(ctx, `INSERT INTO bot_account_squads(tenant_id,legacy_id,source_uuid) VALUES($1::uuid,$2,$3::uuid)`, tenant, id, group); err != nil {
			return false, err
		}
	}
	return true, nil
}
func botRebuildChangedAccess(ctx context.Context, tx pgx.Tx, client botLockedClient, before []string) (int, error) {
	after, err := clientAccessNodes(ctx, tx, client.ID, client.Credential)
	if err != nil {
		return 0, err
	}
	all := map[string]bool{}
	for _, id := range append(before, after...) {
		all[id] = true
	}
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		state, release, err := buildNodeDesiredStateTx(ctx, tx, id)
		if err != nil {
			return 0, err
		}
		if err = saveDesiredStateTx(ctx, tx, id, state, release); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
func (p *Postgres) BotCreateUser(ctx context.Context, key string, input BotCreateInput) (botResult, error) {
	if !botUsername.MatchString(input.Username) || input.DurationDays < 1 || input.DurationDays > 3650 || input.TrafficLimitStrategy != "NO_RESET" || input.TrafficLimitBytes < 0 || input.TrafficLimitBytes > maxTrafficCounter || input.HWIDDeviceLimit < 0 || input.HWIDDeviceLimit > 1000 || !botText(input.Description, 4096) || input.TelegramID != nil && (*input.TelegramID < 0 || *input.TelegramID > 9007199254740991) {
		return botResult{}, ErrBotBridgeRequest
	}
	var err error
	input.ActiveInternalSquads, err = botSquads(input.ActiveInternalSquads, false)
	if err != nil {
		return botResult{}, err
	}
	fp, err := botFingerprint("POST", "/users", input)
	if err != nil {
		return botResult{}, err
	}
	return p.runBotOperation(ctx, key, fp, func(tx pgx.Tx, tenant string) (out botResult, err error) {
		defer func() { err = botSQLError(err) }()
		if err = checkTenantQuota(ctx, tx, tenant, "client"); err != nil {
			return out, err
		}
		if err = botValidateSquads(ctx, tx, tenant, input.ActiveInternalSquads); err != nil {
			return out, err
		}
		var id int64
		err = tx.QueryRow(ctx, `UPDATE bot_profiles SET next_native_id=next_native_id+1 WHERE tenant_id=$1::uuid AND next_native_id<=9007199254740991 RETURNING next_native_id-1`, tenant).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return out, ErrBotBridgeConflict
		}
		if err != nil {
			return out, err
		}
		var client botLockedClient
		err = tx.QueryRow(ctx, `INSERT INTO vpn_clients(tenant_id,name,expires_at) VALUES($1::uuid,$2,now()+make_interval(days=>$3)) RETURNING id::text,name,vless_uuid::text`, tenant, input.Username, input.DurationDays).Scan(&client.ID, &client.Name, &client.Credential)
		if err != nil {
			return out, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO vpn_client_continuous_quotas(client_id,limit_bytes,baseline_bytes,baseline_at) VALUES($1::uuid,$2,0,now())`, client.ID, input.TrafficLimitBytes)
		if err != nil {
			return out, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO bot_accounts(tenant_id,legacy_id,client_id,username,telegram_id,description,hwid_device_limit,lifetime_offset_bytes,source_created_at) VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7,0,now())`, tenant, id, client.ID, input.Username, input.TelegramID, input.Description, input.HWIDDeviceLimit)
		if err != nil {
			return out, err
		}
		if err = syncNativeBotDeviceLimitTx(ctx, tx, tenant, client.ID, input.HWIDDeviceLimit); err != nil {
			return out, err
		}
		if _, err = botSetSquads(ctx, tx, tenant, id, input.ActiveInternalSquads); err != nil {
			return out, err
		}
		alias, err := security.NewToken(24)
		if err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO bot_subscription_aliases(alias,tenant_id,legacy_id) VALUES($1,$2::uuid,$3)`, alias, tenant, id); err != nil {
			return out, err
		}
		rebuilds, err := botRebuildChangedAccess(ctx, tx, client, nil)
		if err != nil {
			return out, err
		}
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'bot_bridge.created',$2,$3,jsonb_build_object('client_id',$4::text,'numeric_id',$5::bigint,'rebuild_count',$6::integer))`, tenant, actor, actorID, client.ID, id, rebuilds)
		if err != nil {
			return out, err
		}
		raw, err := botUserTx(ctx, tx, tenant, id)
		if err != nil {
			return out, err
		}
		out, err = botResponse(raw)
		out.Status = 201
		return out, err
	})
}
func (p *Postgres) BotPatchUser(ctx context.Context, key string, input BotPatchInput) (botResult, error) {
	if input.ID < 1 || input.ID > 9007199254740991 || input.ExpireAt != nil && (input.ExpireAt.IsZero() || input.ExpireAt.Year() < 1970 || input.ExpireAt.Year() > 9999) || input.TrafficLimitBytes != nil && (*input.TrafficLimitBytes < 0 || *input.TrafficLimitBytes > maxTrafficCounter) || input.HWIDDeviceLimit != nil && (*input.HWIDDeviceLimit < 0 || *input.HWIDDeviceLimit > 1000) || input.Description != nil && !botText(*input.Description, 4096) {
		return botResult{}, ErrBotBridgeRequest
	}
	if input.ExpireAt != nil {
		at := input.ExpireAt.UTC().Truncate(time.Microsecond)
		input.ExpireAt = &at
	}
	if input.ActiveInternalSquads != nil {
		groups, err := botSquads(*input.ActiveInternalSquads, true)
		if err != nil {
			return botResult{}, err
		}
		input.ActiveInternalSquads = &groups
	}
	fp, err := botFingerprint("PATCH", "/users", input)
	if err != nil {
		return botResult{}, err
	}
	return p.runBotMutation(ctx, key, fp, false, func(tx pgx.Tx, tenant string) (botResult, error) {
		client, err := botLockClient(ctx, tx, tenant, input.ID)
		if err != nil {
			return botResult{}, err
		}
		before, err := clientAccessNodes(ctx, tx, client.ID, client.Credential)
		if err != nil {
			return botResult{}, err
		}
		if input.ExpireAt != nil {
			_, err = tx.Exec(ctx, `UPDATE vpn_clients SET expires_at=$2,updated_at=now() WHERE id=$1::uuid AND expires_at IS DISTINCT FROM $2`, client.ID, *input.ExpireAt)
			if err != nil {
				return botResult{}, err
			}
		}
		if input.TrafficLimitBytes != nil {
			_, err = tx.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET limit_bytes=$2,updated_at=now() WHERE client_id=$1::uuid AND limit_bytes<>$2`, client.ID, *input.TrafficLimitBytes)
			if err != nil {
				return botResult{}, err
			}
		}
		if input.HWIDDeviceLimit != nil {
			if err = syncNativeBotDeviceLimitTx(ctx, tx, tenant, client.ID, *input.HWIDDeviceLimit); err != nil {
				return botResult{}, err
			}
			_, err = tx.Exec(ctx, `UPDATE bot_accounts SET hwid_device_limit=$3,updated_at=now() WHERE tenant_id=$1::uuid AND legacy_id=$2 AND hwid_device_limit IS DISTINCT FROM $3`, tenant, input.ID, *input.HWIDDeviceLimit)
			if err != nil {
				return botResult{}, err
			}
		}
		if input.Description != nil {
			_, err = tx.Exec(ctx, `UPDATE bot_accounts SET description=$3,updated_at=now() WHERE tenant_id=$1::uuid AND legacy_id=$2 AND description IS DISTINCT FROM $3`, tenant, input.ID, *input.Description)
			if err != nil {
				return botResult{}, err
			}
		}
		groupsChanged := false
		if input.ActiveInternalSquads != nil {
			groupsChanged, err = botSetSquads(ctx, tx, tenant, input.ID, *input.ActiveInternalSquads)
			if err != nil {
				return botResult{}, err
			}
		}
		var eligible bool
		err = tx.QueryRow(ctx, `SELECT status='active' AND (expires_at IS NULL OR expires_at>now()) AND NOT vpn_client_quota_exceeded(id) FROM vpn_clients WHERE id=$1::uuid`, client.ID).Scan(&eligible)
		if err != nil {
			return botResult{}, err
		}
		rebuilds := 0
		if groupsChanged || eligible != client.Eligible {
			rebuilds, err = botRebuildChangedAccess(ctx, tx, client, before)
			if err != nil {
				return botResult{}, err
			}
		}
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'bot_bridge.updated',$2,$3,jsonb_build_object('client_id',$4::text,'numeric_id',$5::bigint,'rebuild_count',$6::integer))`, tenant, actor, actorID, client.ID, input.ID, rebuilds)
		if err != nil {
			return botResult{}, err
		}
		raw, err := botUserTx(ctx, tx, tenant, input.ID)
		if err != nil {
			return botResult{}, err
		}
		return botResponse(raw)
	})
}
