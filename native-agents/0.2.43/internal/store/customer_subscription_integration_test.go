//go:build integration

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestCustomerNativeRenewalIntegration(t *testing.T) {
	ctx, p, tenant, importID, digest := botFixture(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := p.PrepareBotBridge(ctx, tenant, importID, digest)
	check(err)
	_, err = p.PrepareRemnawaveNoResetQuota(ctx, importID, tenant, digest)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	op := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	expiry := time.Now().UTC().Add(7 * 24 * time.Hour).Truncate(time.Microsecond)
	client, err := p.CreateVPNClient(ctx, tenant, "Native customer renewal", &expiry)
	check(err)
	_, err = p.SetVPNClientLimits(ctx, client.ID, 4096, 0)
	check(err)
	_, err = p.SetRegisteredDeviceLimit(ctx, client.ID, 2)
	check(err)
	proof := SubscriptionDeviceProof{TokenID: bytes.Repeat([]byte{55}, 16), TokenHash: bytes.Repeat([]byte{65}, 32), TokenVersion: 1}
	_, err = p.CreateVPNClientSubscription(ctx, client.ID, proof.TokenID, proof.TokenVersion, proof.TokenHash, "synthetic")
	check(err)
	resolved, err := p.ResolveCustomerSubscription(op, proof)
	check(err)
	if resolved.ClientID != client.ID || resolved.BotID != nil || resolved.Info.Name != client.Name || resolved.Info.LimitBytes != 4096 {
		t.Fatal("wrong native context")
	}
	for _, role := range []string{"viewer", "reseller", ""} {
		if _, err = p.ResolveCustomerSubscription(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: role}), proof); !errors.Is(err, ErrNotFound) {
			t.Fatal("unprivileged context disclosure")
		}
	}
	foreign, err := p.CreateTenant(ctx, "Customer other tenant")
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO bot_profiles(tenant_id,profile_kind,subscription_base,state,source_identity_reviewed,activated_at) VALUES($1::uuid,'native','https://foreign.example.test/sub','active',true,now())`, foreign.ID)
	check(err)
	if _, err = p.ResolveCustomerSubscription(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"}), proof); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign context disclosure")
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_subscriptions WHERE client_id=$1::uuid AND last_access_at IS NOT NULL`, client.ID).Scan(&count))
	if count != 0 {
		t.Fatal("context registered access")
	}
	key := strings.Repeat("a", 64)
	var wg sync.WaitGroup
	failures := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := p.CustomerRenewNative(op, client.ID, 30, key); failures <- err }()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		check(err)
	}
	var after time.Time
	var credential string
	var limit int
	deviceKey := strings.Repeat("f", 64)
	deviceResult, err := p.CustomerNativeDeviceLimit(op, client.ID, 2, 3, deviceKey)
	check(err)
	deviceReplay, err := p.CustomerNativeDeviceLimit(op, client.ID, 2, 3, deviceKey)
	check(err)
	var deviceJSON, replayDeviceJSON any
	check(json.Unmarshal(deviceResult.Body, &deviceJSON))
	check(json.Unmarshal(deviceReplay.Body, &replayDeviceJSON))
	if !reflect.DeepEqual(deviceJSON, replayDeviceJSON) {
		t.Fatal("device purchase replay changed the result")
	}
	if _, err = p.CustomerNativeDeviceLimit(op, client.ID, 3, 4, deviceKey); !errors.Is(err, ErrBotBridgeConflict) {
		t.Fatal("same payment changed the purchased device count")
	}
	if _, err = p.CustomerNativeDeviceLimit(op, client.ID, 2, 4, strings.Repeat("9", 64)); !errors.Is(err, ErrBotBridgeRequest) {
		t.Fatal("nonconsecutive device purchase accepted")
	}
	if _, err = p.CustomerNativeDeviceLimit(op, client.ID, 2, 3, ""); !errors.Is(err, ErrBotBridgeRequest) {
		t.Fatal("unkeyed device-limit mutation")
	}
	if _, err = p.CustomerNativeDeviceLimit(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"}), client.ID, 3, 4, strings.Repeat("8", 64)); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign tenant raised a device limit")
	}
	check(p.Pool.QueryRow(ctx, `SELECT expires_at,vless_uuid::text,registered_device_limit FROM vpn_clients WHERE id=$1::uuid`, client.ID).Scan(&after, &credential, &limit))
	if after.Sub(expiry) != 30*24*time.Hour || credential != client.VLESSUUID || limit != 3 {
		t.Fatal("renewal changed identity, devices, or applied twice")
	}
	usage, err := p.VPNClientUsage(ctx, client.ID)
	check(err)
	if usage.ResetPolicy != "MONTH" || usage.TrafficLimitBytes != 4096 || usage.UsedBytes != 0 {
		t.Fatal("renewal changed quota accounting")
	}
	if _, err = p.CustomerRenewNative(op, client.ID, 31, key); !errors.Is(err, ErrBotBridgeConflict) {
		t.Fatal("same payment changed duration")
	}
	if _, err = p.CustomerRenewNative(op, client.ID, 30, ""); !errors.Is(err, ErrBotBridgeRequest) {
		t.Fatal("unkeyed renewal")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='disabled' WHERE id=$1::uuid`, client.ID)
	check(err)
	if _, err = p.CustomerRenewNative(op, client.ID, 30, strings.Repeat("b", 64)); !errors.Is(err, ErrBotBridgeConflict) {
		t.Fatal("administrative suspension bypassed")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET status='active',expires_at=NULL WHERE id=$1::uuid`, client.ID)
	check(err)
	if _, err = p.CustomerRenewNative(op, client.ID, 30, strings.Repeat("c", 64)); !errors.Is(err, ErrBotBridgeConflict) {
		t.Fatal("unlimited expiry reduced")
	}
	// Device operations preserve native credentials and cannot reach another tenant.
	var deviceID string
	check(p.Pool.QueryRow(ctx, `INSERT INTO bot_devices(tenant_id,client_id,hwid,created_at,updated_at) VALUES($1::uuid,$2::uuid,'synthetic-native-device',now(),now()) RETURNING id::text`, tenant, client.ID).Scan(&deviceID))
	_, err = p.CustomerNativeDevices(op, proof, "list", "", "", "", nil)
	check(err)
	_, err = p.CustomerNativeDevices(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"}), proof, "list", "", "", "", nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign native devices exposed")
	}
	_, err = p.CustomerNativeDevices(op, proof, "remove", deviceID, strings.Repeat("d", 64), "", nil)
	check(err)
	_, err = p.CustomerNativeDevices(op, proof, "remove", deviceID, strings.Repeat("d", 64), "", nil)
	check(err)
	replacement := strings.Repeat("n", 75)
	replacementHash := bytes.Repeat([]byte{99}, 32)
	result, err := p.CustomerNativeDevices(op, proof, "rotate", "", strings.Repeat("e", 64), replacement, replacementHash)
	check(err)
	replay, err := p.CustomerNativeDevices(op, proof, "rotate", "", strings.Repeat("e", 64), replacement, replacementHash)
	check(err)
	var firstJSON, replayJSON any
	check(json.Unmarshal(result.Body, &firstJSON))
	check(json.Unmarshal(replay.Body, &replayJSON))
	if !reflect.DeepEqual(firstJSON, replayJSON) {
		t.Fatal("rotation replay changed link")
	}
	if _, err = p.ResolveCustomerSubscription(op, proof); !errors.Is(err, ErrNotFound) {
		t.Fatal("old native proof accepted after rotation")
	}
	proof.TokenVersion++
	proof.TokenHash = replacementHash
	_, err = p.ResolveCustomerSubscription(op, proof)
	check(err)
	check(p.Pool.QueryRow(ctx, `SELECT vless_uuid::text FROM vpn_clients WHERE id=$1::uuid`, client.ID).Scan(&credential))
	if credential != client.VLESSUUID {
		t.Fatal("link rotation changed VPN credentials")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_client_subscriptions SET status='revoked' WHERE client_id=$1::uuid`, client.ID)
	check(err)
	if _, err = p.ResolveCustomerSubscription(op, proof); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked proof accepted")
	}
}
