//go:build integration

package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestCustomerSubscriptionStateIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	tenant, err := p.CreateTenant(ctx, "Synthetic customer payment preflight")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Pool.Exec(ctx, `INSERT INTO bot_profiles(tenant_id,profile_kind,subscription_base,state,source_identity_reviewed,activated_at) VALUES($1::uuid,'native','https://preflight.example.test/sub','active',true,now())`, tenant.ID); err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().UTC().Add(7 * 24 * time.Hour)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "Synthetic private name never returned", &expiry)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.SetRegisteredDeviceLimit(ctx, client.ID, 2); err != nil {
		t.Fatal(err)
	}
	op := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	state, err := p.CustomerSubscriptionState(op, client.ID)
	if err != nil || !state.CanRenew || !state.CanAddDevice || state.DeviceLimit != 2 {
		t.Fatal("active finite subscription was not eligible", err)
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = p.CustomerSubscriptionState(op, client.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("paused billing bridge appeared payable")
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active' WHERE tenant_id=$1::uuid`, tenant.ID); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil || len(fields) != 3 {
		t.Fatal("state response exposed unexpected information")
	}
	for _, role := range []string{"viewer", "reseller", ""} {
		_, err = p.CustomerSubscriptionState(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: role}), client.ID)
		if !errors.Is(err, ErrNotFound) {
			t.Fatal("non-operator could read customer state")
		}
	}
	foreign, err := p.CreateTenant(ctx, "Synthetic foreign preflight tenant")
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.CustomerSubscriptionState(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"}), client.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign tenant state was disclosed")
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()-interval '1 day' WHERE id=$1::uuid`, client.ID); err != nil {
		t.Fatal(err)
	}
	state, err = p.CustomerSubscriptionState(op, client.ID)
	if err != nil || !state.CanRenew {
		t.Fatal("expired native subscription cannot be renewed", err)
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=NULL,registered_device_limit=0 WHERE id=$1::uuid`, client.ID); err != nil {
		t.Fatal(err)
	}
	state, err = p.CustomerSubscriptionState(op, client.ID)
	if err != nil || state.CanRenew || state.CanAddDevice || state.DeviceLimit != 0 {
		t.Fatal("unlimited subscription should not receive unnecessary charges", err)
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET remnawave_hold=true,status='disabled' WHERE id=$1::uuid`, client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = p.CustomerSubscriptionState(op, client.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("held subscription appeared available")
	}
	if _, err = p.CustomerSubscriptionState(op, "00000000-0000-4000-8000-000000000001"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing subscription appeared available")
	}
}
