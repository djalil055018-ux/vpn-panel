//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
)

func botFixture(t *testing.T) (context.Context, *Postgres, string, string, string) {
	t.Helper()
	ctx, p := deletionStore(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, e := p.CreateTenant(ctx, "Synthetic bot "+t.Name())
	check(e)
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	check(e)
	var v map[string]any
	check(json.Unmarshal(raw, &v))
	// Independent origin/credentials for each test in the same disposable DB.
	v["source_origin"] = "https://" + strings.ToLower(t.Name()) + ".example.test"
	users := v["users"].([]any)
	for i, item := range users {
		u := item.(map[string]any)
		u["trafficLimitStrategy"] = "NO_RESET"
		u["shortUuid"] = "synthetic-" + strings.ToLower(t.Name()) + "-" + string(rune('a'+i))
		u["subscriptionUrl"] = "https://subscriptions.example.test/" + u["shortUuid"].(string)
		u["vlessUuid"] = map[int]string{0: "c0000000-0000-4000-8000-", 1: "c0000000-0000-4000-8001-", 2: "c0000000-0000-4000-8002-"}[i] + tenant.ID[len(tenant.ID)-12:]
	}
	users[0].(map[string]any)["telegramId"] = float64(123456789)
	v["devices"] = []any{map[string]any{"userId": float64(1), "hwid": "synthetic-device", "platform": "Android", "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2025-01-01T00:00:00Z", "requestIp": "192.0.2.1", "userAgent": "never-serve-source-agent"}}
	raw, e = json.Marshal(v)
	check(e)
	_, r, e := remnawave.Parse(raw)
	check(e)
	staged, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, r.SHA256)
	check(e)
	return ctx, p, tenant.ID, staged.ID, r.SHA256
}

func TestBotBridgeNativeActionsIntegration(t *testing.T) {
	ctx, p, tenant, importID, digest := botFixture(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	plan, err := p.CreateVPNAccessPlan(ctx, tenant, "Native setup rejection", "test", true)
	check(err)
	if _, err = p.ConfigureNativeBot(ctx, tenant, "https://fresh.example.test/sub/", plan.ID); err != ErrBotBridgeConflict {
		t.Fatal("native setup adopted tenant with imported inventory")
	}
	_, e := p.PrepareBotBridge(ctx, tenant, importID, digest)
	check(e)
	if _, err = p.ConfigureNativeBot(ctx, tenant, "https://fresh.example.test/sub/", plan.ID); err != ErrBotBridgeConflict {
		t.Fatal("native setup converted imported bot profile")
	}
	_, e = p.PrepareRemnawaveNoResetQuota(ctx, importID, tenant, digest)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_clients SET remnawave_hold=false,status='active',expires_at=now()+interval '7 days' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	mappings, e := p.RemnawaveImportClients(ctx, importID, 0, 250)
	check(e)
	id := mappings[0].ClientID
	var initial time.Time
	check(p.Pool.QueryRow(ctx, `SELECT expires_at FROM vpn_clients WHERE id=$1::uuid`, id).Scan(&initial))
	key := strings.Repeat("1", 64)
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := p.BotUserAction(operator, 1, "extend", key, 30); failures <- e }()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		check(e)
	}
	var after time.Time
	check(p.Pool.QueryRow(ctx, `SELECT expires_at FROM vpn_clients WHERE id=$1::uuid`, id).Scan(&after))
	if after.Sub(initial) != 30*24*time.Hour {
		t.Fatal("parallel paid extension applied more than once")
	}
	if _, e = p.BotUserAction(operator, 2, "extend", key, 30); !errors.Is(e, ErrBotBridgeConflict) {
		t.Fatal("paid retry retargeted")
	}
	if _, e = p.BotUserAction(operator, 1, "extend", key, 31); !errors.Is(e, ErrBotBridgeConflict) {
		t.Fatal("paid retry changed days")
	}
	_, e = p.BotUserAction(operator, 1, "extend", strings.Repeat("2", 64), 30)
	check(e)
	check(p.Pool.QueryRow(ctx, `SELECT expires_at FROM vpn_clients WHERE id=$1::uuid`, id).Scan(&after))
	if after.Sub(initial) != 60*24*time.Hour {
		t.Fatal("second paid order lost")
	}
	if _, e = p.BotUserAction(operator, 1, "extend", "", 30); !errors.Is(e, ErrBotBridgeRequest) {
		t.Fatal("unkeyed paid extension accepted")
	}

	_, _, e = p.ImportReviewedPPTP(ctx)
	check(e)
	check(p.ApproveReviewedPPTP(ctx))
	bootstrap := security.HashToken("synthetic-bot-pptp-bootstrap")
	node, e := p.CreateNodeForRuntime(ctx, tenant, "Synthetic bot native rebuild", bootstrap, "pptp")
	check(e)
	_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-bot-pptp-agent"), "0.2.30", "ubuntu", "24.04", "amd64", "pptp")
	check(e)
	_, _, e = p.InitializePPTPRuntime(ctx, node.ID)
	check(e)
	address, port := "synthetic-bot-pptp.example.test", 1723
	service, e := p.CreateVPNService(ctx, node.ID, "Synthetic bot PPTP", "pptp", "0.0.0.0", port, "tcp,gre", "mppe", &address, &port)
	check(e)
	_, e = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET limit_bytes=150,baseline_bytes=100,uplink_bytes=0,downlink_bytes=0 WHERE client_id=$1::uuid`, id)
	check(e)
	_, e = p.AttachVPNClientAndRebuild(ctx, service.ID, id)
	check(e)
	desiredCount := func() int {
		t.Helper()
		var n int
		check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN desired_states d ON d.node_id=n.id AND d.generation=n.desired_generation,jsonb_array_elements(d.document->'services') s,jsonb_array_elements(s->'clients') c WHERE n.id=$1::uuid AND c->>'stats_key'=$2`, node.ID, id).Scan(&n))
		return n
	}
	if desiredCount() != 1 {
		t.Fatal("initial native grant absent")
	}
	_, e = p.BotUserAction(operator, 1, "disable", strings.Repeat("3", 64), 0)
	check(e)
	if desiredCount() != 0 {
		t.Fatal("bot disable left live desired access")
	}
	_, e = p.BotUserAction(operator, 1, "enable", strings.Repeat("4", 64), 0)
	check(e)
	if desiredCount() != 1 {
		t.Fatal("bot enable did not rebuild")
	}
	epoch := strings.Repeat("a", 32)
	deliver := func(seq, up int64) {
		t.Helper()
		check(p.SaveTrafficDelivery(ctx, node.ID, model.TrafficDelivery{RecordedAt: time.Now().UTC(), Snapshot: model.ClientTrafficSnapshot{Sequence: seq, Epoch: epoch, Clients: []model.ClientTraffic{{ClientID: id, Uplink: up}}}}))
	}
	var lifetime int64
	check(p.Pool.QueryRow(ctx, `SELECT lifetime_offset_bytes FROM bot_accounts WHERE tenant_id=$1::uuid AND legacy_id=1`, tenant).Scan(&lifetime))
	deliver(1, 80)
	if desiredCount() != 0 {
		t.Fatal("quota crossing left native access")
	}
	resetKey := strings.Repeat("5", 64)
	_, e = p.BotUserAction(operator, 1, "reset-traffic", resetKey, 0)
	check(e)
	if desiredCount() != 1 {
		t.Fatal("explicit reset did not restore eligible native access")
	}
	deliver(1, 80)
	deliver(2, 90)
	usage, e := p.VPNClientUsage(ctx, id)
	check(e)
	if usage.UsedBytes != 10 {
		t.Fatal("reset discarded node cursor or re-counted old traffic")
	}
	_, e = p.BotUserAction(operator, 1, "reset-traffic", resetKey, 0)
	check(e)
	usage, e = p.VPNClientUsage(ctx, id)
	check(e)
	if usage.UsedBytes != 10 {
		t.Fatal("lost reset response wiped newly accrued traffic")
	}
	var keptLifetime int64
	check(p.Pool.QueryRow(ctx, `SELECT b.lifetime_offset_bytes+q.uplink_bytes+q.downlink_bytes FROM bot_accounts b JOIN vpn_client_continuous_quotas q ON q.client_id=b.client_id WHERE b.tenant_id=$1::uuid AND b.legacy_id=1`, tenant).Scan(&keptLifetime))
	if keptLifetime != lifetime+90 {
		t.Fatal("reset erased lifetime traffic")
	}
	var oldCredential, oldPassword, oldAlias, newCredential, newPassword, newAlias string
	check(p.Pool.QueryRow(ctx, `SELECT c.vless_uuid::text,k.password,a.alias FROM vpn_clients c JOIN vpn_client_pptp k ON k.client_id=c.id JOIN bot_accounts b ON b.client_id=c.id JOIN bot_subscription_aliases a ON a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id AND a.state='active' WHERE c.id=$1::uuid`, id).Scan(&oldCredential, &oldPassword, &oldAlias))
	_, e = p.CreateVPNClientSubscription(ctx, id, bytes.Repeat([]byte{0x42}, 16), 1, bytes.Repeat([]byte{0x42}, 32), "synthetic-bot-native-sub")
	check(e)
	revokeKey := strings.Repeat("9", 64)
	_, e = p.BotUserAction(operator, 1, "revoke", revokeKey, 0)
	check(e)
	check(p.Pool.QueryRow(ctx, `SELECT c.vless_uuid::text,k.password,a.alias FROM vpn_clients c JOIN vpn_client_pptp k ON k.client_id=c.id JOIN bot_accounts b ON b.client_id=c.id JOIN bot_subscription_aliases a ON a.tenant_id=b.tenant_id AND a.legacy_id=b.legacy_id AND a.state='active' WHERE c.id=$1::uuid`, id).Scan(&newCredential, &newPassword, &newAlias))
	if oldCredential == newCredential || oldPassword == newPassword || oldAlias == newAlias {
		t.Fatal("revoke changed link without rotating runtime credential")
	}
	var revoked bool
	check(p.Pool.QueryRow(ctx, `SELECT a.state='revoked' AND NOT EXISTS(SELECT 1 FROM vpn_client_subscriptions s WHERE s.client_id=$2::uuid AND s.status='active') FROM bot_subscription_aliases a WHERE a.alias=$1`, oldAlias, id).Scan(&revoked))
	if !revoked {
		t.Fatal("revoke left old public subscriptions active")
	}
	_, e = p.BotUserAction(operator, 1, "revoke", revokeKey, 0)
	check(e)
	var kept string
	check(p.Pool.QueryRow(ctx, `SELECT vless_uuid::text FROM vpn_clients WHERE id=$1::uuid`, id).Scan(&kept))
	if kept != newCredential {
		t.Fatal("lost revoke response rotated keys again")
	}
	usage, e = p.VPNClientUsage(ctx, id)
	check(e)
	if usage.UsedBytes != 10 {
		t.Fatal("revoke reset usage")
	}
	hwid := "synthetic-device"
	_, e = p.BotDeleteDevices(operator, 1, &hwid, strings.Repeat("6", 64))
	check(e)
	device, e := p.BotDevices(operator, 1)
	check(e)
	if string(device) != `{"devices": []}` {
		var d struct{ Devices []any }
		check(json.Unmarshal(device, &d))
		if len(d.Devices) != 0 {
			t.Fatal("device still present")
		}
	}
	deleteKey := strings.Repeat("7", 64)
	_, e = p.BotUserAction(operator, 1, "delete", deleteKey, 0)
	check(e)
	if desiredCount() != 0 {
		t.Fatal("bot deletion left desired client")
	}
	_, e = p.BotUserAction(operator, 1, "delete", deleteKey, 0)
	check(e)
	if _, e = p.BotUserAction(operator, 1, "extend", strings.Repeat("8", 64), 30); !errors.Is(e, ErrNotFound) {
		t.Fatal("deleted account revived")
	}
	var aliases int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_subscription_aliases WHERE tenant_id=$1::uuid AND legacy_id=1 AND state='active'`, tenant).Scan(&aliases))
	if aliases != 0 {
		t.Fatal("bot delete retained alias")
	}
}

func TestBotBridgeHeldPreparationIntegration(t *testing.T) {
	ctx, p, tenant, importID, digest := botFixture(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, restricted := range []context.Context{WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}}), WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})} {
		if _, e := p.PrepareBotBridge(restricted, tenant, importID, digest); !errors.Is(e, ErrNotFound) {
			t.Fatal("non-owner prepared bridge")
		}
	}
	if _, e := p.PrepareBotBridge(ctx, tenant, importID, strings.Repeat("0", 64)); !errors.Is(e, ErrRemnawaveReview) {
		t.Fatal("wrong digest accepted")
	}
	for i := 0; i < 2; i++ {
		out, e := p.PrepareBotBridge(ctx, tenant, importID, digest)
		check(e)
		if out.Users != 3 || out.Devices != 1 || out.Squads != 1 || out.MigrationReady {
			t.Fatal("held metadata projection count")
		}
	}
	var users, aliases, grants, subscriptions, devices int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_accounts WHERE tenant_id=$1::uuid`, tenant).Scan(&users))
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_subscription_aliases WHERE tenant_id=$1::uuid AND state='active'`, tenant).Scan(&aliases))
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_access_plans WHERE tenant_id=$1::uuid`, tenant).Scan(&grants))
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_subscriptions WHERE tenant_id=$1::uuid`, tenant).Scan(&subscriptions))
	if users != 3 || aliases != 3 || grants != 0 || subscriptions != 0 {
		t.Fatal("staging altered live access")
	}
	var created, updated time.Time
	check(p.Pool.QueryRow(ctx, `SELECT created_at,updated_at FROM bot_devices WHERE tenant_id=$1::uuid`, tenant).Scan(&created, &updated))
	if created.Year() != 2026 || updated.Year() != 2025 {
		t.Fatal("source device history rewritten")
	}
	var telegram int64
	check(p.Pool.QueryRow(ctx, `SELECT telegram_id FROM bot_accounts WHERE tenant_id=$1::uuid AND legacy_id=1`, tenant).Scan(&telegram))
	if telegram != 123456789 {
		t.Fatal("Telegram identity changed")
	}
	mappings, e := p.RemnawaveImportClients(ctx, importID, 0, 250)
	check(e)
	_, e = p.DeleteVPNClient(ctx, mappings[0].ClientID, mappings[0].Name)
	check(e)
	var tombstone bool
	check(p.Pool.QueryRow(ctx, `SELECT client_id IS NULL AND deleted_client_id=$2::uuid AND deleted_at IS NOT NULL AND telegram_id IS NULL FROM bot_accounts WHERE tenant_id=$1::uuid AND legacy_id=1`, tenant, mappings[0].ClientID).Scan(&tombstone))
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_devices WHERE tenant_id=$1::uuid`, tenant).Scan(&devices))
	if !tombstone || devices != 0 {
		t.Fatal("native delete failed to preserve tombstone/remove devices")
	}
	out, e := p.PrepareBotBridge(ctx, tenant, importID, digest)
	check(e)
	if out.Deleted != 1 || out.Users != 2 || out.Devices != 0 {
		t.Fatal("replay resurrected deleted identity")
	}
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_subscription_aliases WHERE tenant_id=$1::uuid AND state='active'`, tenant).Scan(&aliases))
	if aliases != 2 {
		t.Fatal("deleted alias became active")
	}
	clients, e := p.ListVPNClients(ctx, tenant)
	check(e)
	for _, c := range clients {
		if !c.RemnawaveHold || c.Status != "disabled" {
			t.Fatal("metadata preparation released hold")
		}
	}
}

func TestBotBridgeDurableOperationIntegration(t *testing.T) {
	ctx, p, tenant, importID, digest := botFixture(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := p.PrepareBotBridge(ctx, tenant, importID, digest)
	check(e)
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	key := strings.Repeat("a", 64)
	fingerprint, e := botFingerprint("POST", "/users/1/actions/extend", map[string]any{"days": 30})
	check(e)
	var calls atomic.Int64
	effect := func(tx pgx.Tx, scope string) (botResult, error) {
		calls.Add(1)
		// A real transactional change independent of receipts allows rollback and
		// concurrency assertions without pretending a mocked ledger is PostgreSQL.
		_, e := tx.Exec(ctx, `UPDATE bot_profiles SET next_native_id=next_native_id+1 WHERE tenant_id=$1::uuid`, scope)
		return botResult{Status: 200, Body: json.RawMessage(`{"response":{"id":1,"applied":true}}`)}, e
	}
	if _, e = p.runBotOperation(operator, key, fingerprint, effect); !errors.Is(e, ErrBotBridgeHeld) || calls.Load() != 0 {
		t.Fatal("held bot mutation admitted")
	}
	if _, e = p.runBotOperation(ctx, key, fingerprint, effect); !errors.Is(e, ErrNotFound) {
		t.Fatal("root context accepted instead of tenant operator")
	}
	// Synthetic activation only in the disposable database; production has no
	// API for bypassing the still-unimplemented runtime/subscription cutover.
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := p.runBotOperation(operator, key, fingerprint, effect)
			if e == nil && r.Status != 200 {
				e = errors.New("receipt status")
			}
			failures <- e
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		check(e)
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent repeats applied more than once")
	}
	// Recreate the Store (as after a process restart/lost response); receipt lives
	// in the DB, not in a process cache or an in-flight HTTP handler.
	restarted, e := NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	check(e)
	defer restarted.Close()
	_, e = restarted.runBotOperation(operator, key, fingerprint, effect)
	check(e)
	if calls.Load() != 1 {
		t.Fatal("restart replay applied again")
	}
	for _, changed := range []struct {
		path string
		days int
	}{{"/users/2/actions/extend", 30}, {"/users/1/actions/extend", 31}} {
		fp, e := botFingerprint("POST", changed.path, map[string]any{"days": changed.days})
		check(e)
		if _, e = p.runBotOperation(operator, key, fp, effect); !errors.Is(e, ErrBotBridgeConflict) {
			t.Fatal("changed request reused receipt")
		}
	}
	_, e = p.runBotOperation(operator, strings.Repeat("b", 64), fingerprint, effect)
	check(e)
	if calls.Load() != 2 {
		t.Fatal("distinct legitimate operation suppressed")
	}
	sentinel := errors.New("synthetic effect fails after write")
	failing := func(tx pgx.Tx, scope string) (botResult, error) {
		_, e := effect(tx, scope)
		if e != nil {
			return botResult{}, e
		}
		return botResult{}, sentinel
	}
	if _, e = p.runBotOperation(operator, strings.Repeat("c", 64), fingerprint, failing); !errors.Is(e, sentinel) {
		t.Fatal("failed effect unexpectedly committed")
	}
	var next int64
	var receipts int
	check(p.Pool.QueryRow(ctx, `SELECT next_native_id FROM bot_profiles WHERE tenant_id=$1::uuid`, tenant).Scan(&next))
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_operations WHERE tenant_id=$1::uuid`, tenant).Scan(&receipts))
	if next != 4503599627370498 || receipts != 2 {
		t.Fatal("effect/receipt did not roll back together")
	}
	_, e = p.runBotOperation(operator, strings.Repeat("c", 64), fingerprint, effect)
	check(e)
	for _, role := range []string{"viewer", "reseller"} {
		if _, e = p.runBotOperation(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: role}), key, fingerprint, effect); !errors.Is(e, ErrNotFound) {
			t.Fatal("read-only role mutated")
		}
	}
	foreign, e := p.CreateTenant(ctx, "Foreign bridge operator")
	check(e)
	if _, e = p.runBotOperation(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"}), key, fingerprint, effect); !errors.Is(e, ErrBotBridgeHeld) {
		t.Fatal("foreign tenant replayed receipt")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	if _, e = p.runBotOperation(operator, key, fingerprint, effect); !errors.Is(e, ErrBotBridgeHeld) {
		t.Fatal("paused profile replayed mutation")
	}
}

func TestBotBridgeReadIsolationIntegration(t *testing.T) {
	ctx, p, tenant, importID, digest := botFixture(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := p.PrepareBotBridge(ctx, tenant, importID, digest)
	check(e)
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	if _, e = p.BotUser(operator, 1, nil); !errors.Is(e, ErrBotBridgeHeld) {
		t.Fatal("held metadata exposed to bot")
	}
	_, e = p.PrepareRemnawaveNoResetQuota(ctx, importID, tenant, digest)
	check(e)
	// Only the synthetic DB bypasses the future owner-reviewed activation process.
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_clients SET remnawave_hold=false,status='active' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	status, e := p.BotBridgeStatus(operator)
	check(e)
	if status.MigrationReady {
		t.Fatal("incomplete bridge advertised full readiness")
	}
	raw, e := p.BotUser(operator, 1, nil)
	check(e)
	for _, secret := range []string{"vlessUuid", "trojanPassword", "ssPassword", "c0000000-", "synthetic-trojan", "synthetic-ss", "requestIp", "userAgent", "never-serve-source-agent"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("source-only secret escaped bridge")
		}
	}
	var user struct {
		ID                   int64
		TelegramID           int64
		Username             string
		TrafficLimitStrategy string
		UsedTrafficBytes     int64
	}
	check(json.Unmarshal(raw, &user))
	if user.ID != 1 || user.TelegramID != 123456789 || user.TrafficLimitStrategy != "NO_RESET" || user.UsedTrafficBytes != 123456 {
		t.Fatal("numeric identity/quota projection mismatch")
	}
	name := user.Username
	byName, e := p.BotUser(operator, 0, &name)
	check(e)
	if string(raw) != string(byName) {
		t.Fatal("username resolved another identity")
	}
	var cursor int64
	seen := map[int64]bool{}
	for page := 0; page < 3; page++ {
		out, e := p.BotUsers(operator, BotUserFilter{After: cursor, Size: 1})
		check(e)
		if len(out.Users) != 1 {
			t.Fatal("pagination page size")
		}
		var id struct{ ID int64 }
		check(json.Unmarshal(out.Users[0], &id))
		if seen[id.ID] || id.ID <= cursor {
			t.Fatal("non-monotonic cursor")
		}
		seen[id.ID] = true
		if page < 2 {
			if out.NextCursor == nil || *out.NextCursor != id.ID {
				t.Fatal("next cursor missing")
			}
			cursor = *out.NextCursor
		} else if out.NextCursor != nil {
			t.Fatal("trailing phantom page")
		}
	}
	tg := int64(123456789)
	out, e := p.BotUsers(operator, BotUserFilter{Size: 1000, TelegramID: &tg})
	check(e)
	if len(out.Users) != 1 {
		t.Fatal("Telegram exact filter")
	}
	email := "absent@example.test"
	out, e = p.BotUsers(operator, BotUserFilter{Size: 1000, Email: &email})
	check(e)
	if len(out.Users) != 0 {
		t.Fatal("email filter broadened")
	}
	devices, e := p.BotDevices(operator, 1)
	check(e)
	if !strings.Contains(string(devices), "synthetic-device") || strings.Contains(string(devices), "requestIp") || strings.Contains(string(devices), "userAgent") {
		t.Fatal("device projection")
	}
	for _, call := range []func() error{
		func() error { _, e := p.BotUser(operator, 999, nil); return e },
		func() error { _, e := p.BotDevices(operator, 999); return e },
	} {
		if !errors.Is(call(), ErrNotFound) {
			t.Fatal("unknown identity exposed")
		}
	}
	viewer := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "viewer"})
	if _, e = p.BotUser(viewer, 1, nil); !errors.Is(e, ErrNotFound) {
		t.Fatal("viewer read bearer alias")
	}
	mappings, e := p.RemnawaveImportClients(ctx, importID, 0, 250)
	check(e)
	_, e = p.DeleteVPNClient(ctx, mappings[0].ClientID, mappings[0].Name)
	check(e)
	if _, e = p.BotUser(operator, 1, nil); !errors.Is(e, ErrNotFound) {
		t.Fatal("deleted numeric identity still readable")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	if _, e = p.BotDevices(operator, 2); !errors.Is(e, ErrBotBridgeHeld) {
		t.Fatal("paused device lookup accepted")
	}
}

func TestBotBridgeCreateAndSquadIsolationIntegration(t *testing.T) {
	ctx, p, tenant, importID, digest := botFixture(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e := p.PrepareBotBridge(ctx, tenant, importID, digest)
	check(e)
	_, e = p.PrepareRemnawaveNoResetQuota(ctx, importID, tenant, digest)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_clients SET remnawave_hold=false,status='active' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	var squad string
	check(p.Pool.QueryRow(ctx, `SELECT source_uuid::text FROM bot_squads WHERE tenant_id=$1::uuid`, tenant).Scan(&squad))
	create := BotCreateInput{Username: "synthetic_paid_order", DurationDays: 30, TrafficLimitStrategy: "NO_RESET", TrafficLimitBytes: 1000, ActiveInternalSquads: []string{squad}}
	key := strings.Repeat("a", 64)
	if _, e = p.BotCreateUser(operator, key, create); !errors.Is(e, ErrBotBridgeConflict) {
		t.Fatal("unmapped squad created account")
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM bot_accounts WHERE tenant_id=$1::uuid`, tenant).Scan(&count))
	if count != 3 {
		t.Fatal("failed create left orphan account")
	}
	_, _, e = p.ImportReviewedPPTP(ctx)
	check(e)
	check(p.ApproveReviewedPPTP(ctx))
	bootstrap := security.HashToken("synthetic-bot-create-bootstrap")
	node, e := p.CreateNodeForRuntime(ctx, tenant, "Synthetic bot grant node", bootstrap, "pptp")
	check(e)
	_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-bot-create-agent"), "0.2.30", "ubuntu", "24.04", "amd64", "pptp")
	check(e)
	_, _, e = p.InitializePPTPRuntime(ctx, node.ID)
	check(e)
	address, port := "synthetic-create.example.test", 1723
	service, e := p.CreateVPNService(ctx, node.ID, "Synthetic create service", "pptp", "0.0.0.0", port, "tcp,gre", "mppe", &address, &port)
	check(e)
	_, e = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(e)
	plan, e := p.CreateVPNAccessPlan(ctx, tenant, "Source squad mapped plan", "bot-source", true)
	check(e)
	_, e = p.SetVPNAccessPlanService(ctx, plan.ID, service.ID, true)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE bot_squads SET plan_id=$2::uuid WHERE tenant_id=$1::uuid AND source_uuid=$3::uuid`, tenant, plan.ID, squad)
	check(e)
	result, e := p.BotCreateUser(operator, key, create)
	check(e)
	var response struct {
		Response struct {
			ID        int64
			ShortUUID string
			ExpireAt  time.Time
		}
	}
	check(json.Unmarshal(result.Body, &response))
	id := response.Response.ID
	if result.Status != 201 || id != 4503599627370496 || len(response.Response.ShortUUID) != 32 {
		t.Fatal("new identity did not use reserved numeric namespace")
	}
	again, e := p.BotCreateUser(operator, key, create)
	check(e)
	var repeated struct {
		Response struct {
			ID       int64
			ExpireAt time.Time
		}
	}
	check(json.Unmarshal(again.Body, &repeated))
	if repeated.Response.ID != id || !repeated.Response.ExpireAt.Equal(response.Response.ExpireAt) {
		t.Fatal("creation retry reallocated identity/expiry")
	}
	changed := create
	changed.DurationDays = 31
	if _, e = p.BotCreateUser(operator, key, changed); !errors.Is(e, ErrBotBridgeConflict) {
		t.Fatal("changed creation replay accepted")
	}
	var cid string
	check(p.Pool.QueryRow(ctx, `SELECT client_id::text FROM bot_accounts WHERE tenant_id=$1::uuid AND legacy_id=$2`, tenant, id).Scan(&cid))
	desiredCount := func() int {
		t.Helper()
		var n int
		check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM nodes n JOIN desired_states d ON d.node_id=n.id AND d.generation=n.desired_generation,jsonb_array_elements(d.document->'services') s,jsonb_array_elements(s->'clients') c WHERE n.id=$1::uuid AND c->>'stats_key'=$2`, node.ID, cid).Scan(&n))
		return n
	}
	if desiredCount() != 1 {
		t.Fatal("atomic creation lacked effective access")
	}
	empty := []string{}
	_, e = p.BotPatchUser(operator, strings.Repeat("b", 64), BotPatchInput{ID: id, ActiveInternalSquads: &empty})
	check(e)
	if desiredCount() != 0 {
		t.Fatal("empty squads failed to revoke bot grant")
	}
	groups := []string{squad}
	_, e = p.BotPatchUser(operator, strings.Repeat("c", 64), BotPatchInput{ID: id, ActiveInternalSquads: &groups})
	check(e)
	if desiredCount() != 1 {
		t.Fatal("squad restore failed")
	}
	// The native administrator grants the same plan independently. Clearing bot
	// squads removes only bot access; the native assignment must remain intact.
	_, e = p.SetVPNClientAccessPlan(ctx, plan.ID, cid, true)
	check(e)
	_, e = p.BotPatchUser(operator, strings.Repeat("d", 64), BotPatchInput{ID: id, ActiveInternalSquads: &empty})
	check(e)
	if desiredCount() != 1 {
		t.Fatal("bot removed independent native grant")
	}
	_, e = p.SetVPNClientAccessPlan(ctx, plan.ID, cid, false)
	check(e)
	if desiredCount() != 0 {
		t.Fatal("native grant removal failed after bot clear")
	}
	_, e = p.BotPatchUser(operator, strings.Repeat("e", 64), BotPatchInput{ID: id, ActiveInternalSquads: &groups})
	check(e)
	disabled := false
	_, e = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &disabled})
	check(e)
	if desiredCount() != 0 {
		t.Fatal("native plan disable missed bot-owned members")
	}
	enabled := true
	_, e = p.UpdateVPNAccessPlan(ctx, plan.ID, AccessPlanUpdate{Enabled: &enabled})
	check(e)
	if desiredCount() != 1 {
		t.Fatal("native plan enable missed bot-owned members")
	}
	detail, e := p.GetVPNAccessPlan(ctx, plan.ID)
	check(e)
	found := false
	for _, v := range detail.BotClientIDs {
		if v == cid {
			found = true
		}
	}
	if !found || len(detail.ClientIDs) != 0 {
		t.Fatal("native/bot plan membership sources collapsed")
	}
	// Only nodes mapped through this tenant's source squads are visible. Health
	// expiry is evaluated on every request; raw agent errors are never returned.
	_, e = p.CreateNodeForRuntime(ctx, tenant, "Unmapped synthetic node", security.HashToken("unmapped-bot-node"), "pptp")
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE nodes SET applied_generation=desired_generation WHERE id=$1::uuid`, node.ID)
	check(e)
	_, e = p.Pool.Exec(ctx, `INSERT INTO node_health(node_id,healthy,applied_generation,core,core_version,message,checked_at)
 SELECT id,true,desired_generation,'pptp','synthetic','SECRET_AGENT_ERROR_NOT_FOR_BOT',now() FROM nodes WHERE id=$1::uuid
 ON CONFLICT(node_id) DO UPDATE SET healthy=true,checked_at=now(),message=excluded.message,applied_generation=excluded.applied_generation`, node.ID)
	check(e)
	rawNodes, e := p.BotNodes(operator)
	check(e)
	var nodes struct {
		Nodes []struct {
			UUID             string
			IsConnected      bool
			UsersOnline      *int
			UsersOnlineKnown bool
		}
	}
	check(json.Unmarshal(rawNodes, &nodes))
	if len(nodes.Nodes) != 1 || nodes.Nodes[0].UUID != node.ID || !nodes.Nodes[0].IsConnected || nodes.Nodes[0].UsersOnline != nil || nodes.Nodes[0].UsersOnlineKnown || strings.Contains(string(rawNodes), "SECRET_AGENT_ERROR") {
		t.Fatal("node projection exposed foreign/unknown/stale telemetry")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE node_health SET checked_at=now()-interval '2 minutes' WHERE node_id=$1::uuid`, node.ID)
	check(e)
	rawNodes, e = p.BotNodes(operator)
	check(e)
	check(json.Unmarshal(rawNodes, &nodes))
	if nodes.Nodes[0].IsConnected {
		t.Fatal("stale node health reported online")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET baseline_bytes=400,uplink_bytes=100 WHERE client_id=$1::uuid`, cid)
	check(e)
	limit := int64(450)
	_, e = p.BotPatchUser(operator, strings.Repeat("f", 64), BotPatchInput{ID: id, TrafficLimitBytes: &limit})
	check(e)
	usage, e := p.VPNClientUsage(ctx, cid)
	check(e)
	if usage.UsedBytes != 500 || desiredCount() != 0 {
		t.Fatal("limit edit reset usage or failed to revoke")
	}
	limit = 0
	_, e = p.BotPatchUser(operator, strings.Repeat("0", 64), BotPatchInput{ID: id, TrafficLimitBytes: &limit})
	check(e)
	if desiredCount() != 1 {
		t.Fatal("unlimited edit failed to restore access")
	}
	_, e = p.BotUserAction(operator, id, "delete", strings.Repeat("1", 64), 0)
	check(e)
	// A deleted creation receipt can be read, but no new operation can reuse its
	// name/numeric identity or restore its previously valid subscription alias.
	_, e = p.BotCreateUser(operator, key, create)
	check(e)
	if _, e = p.BotCreateUser(operator, strings.Repeat("2", 64), create); !errors.Is(e, ErrBotBridgeConflict) {
		t.Fatal("deleted identity resurrected")
	}
	create.Username = "synthetic_next_paid_order"
	result, e = p.BotCreateUser(operator, strings.Repeat("3", 64), create)
	check(e)
	check(json.Unmarshal(result.Body, &response))
	if response.Response.ID != id+1 {
		t.Fatal("failed or deleted create reused/skipped committed identity")
	}
}
