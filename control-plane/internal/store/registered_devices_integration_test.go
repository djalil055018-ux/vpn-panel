//go:build integration

package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/subscriptioncompat"
)

func TestRegisteredDevicesIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(90*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var db string
	check(p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db))
	if !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	tenant, err := p.CreateTenant(ctx, "Synthetic registered devices")
	check(err)
	foreign, err := p.CreateTenant(ctx, "Synthetic other device tenant")
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "Synthetic devices", nil)
	check(err)
	proof := SubscriptionDeviceProof{TokenID: bytes.Repeat([]byte{1}, 16), TokenHash: bytes.Repeat([]byte{2}, 32), TokenVersion: 1}
	_, err = p.CreateVPNClientSubscription(ctx, client.ID, proof.TokenID, 1, proof.TokenHash, "synthetic")
	check(err)
	value, err := p.RegisteredDevices(ctx, client.ID)
	check(err)
	if value.Limit != 0 || value.Count != 0 {
		t.Fatal("new clients must remain unlimited")
	}
	_, err = p.AdmitSubscriptionDevice(ctx, client.ID, proof, nil, false)
	check(err)
	_, err = p.SetRegisteredDeviceLimit(ctx, client.ID, 2)
	check(err)
	_, err = p.AdmitSubscriptionDevice(ctx, client.ID, proof, nil, false)
	if !errors.Is(err, ErrRegisteredDeviceRequired) {
		t.Fatal("missing HWID must not bypass limit")
	}
	_, err = p.AdmitSubscriptionDevice(ctx, client.ID, proof, &subscriptioncompat.DeviceObservation{HWID: "invalid"}, false)
	if !errors.Is(err, ErrRegisteredDeviceRequired) {
		t.Fatal("malformed HWID must not bypass limit")
	}
	foreignCtx := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"})
	if _, err = p.RegisteredDevices(foreignCtx, client.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign device read allowed")
	}
	if _, err = p.SetRegisteredDeviceLimit(foreignCtx, client.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign limit edit allowed")
	}
	var wg sync.WaitGroup
	outcomes := make(chan struct {
		hwid string
		err  error
	}, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hwid := fmt.Sprintf("synthetic-device-%02d", i)
			_, err := p.AdmitSubscriptionDevice(ctx, client.ID, proof, &subscriptioncompat.DeviceObservation{HWID: hwid}, false)
			outcomes <- struct {
				hwid string
				err  error
			}{hwid, err}
		}(i)
	}
	wg.Wait()
	close(outcomes)
	accepted := []string{}
	for result := range outcomes {
		if result.err == nil {
			accepted = append(accepted, result.hwid)
		} else if !errors.Is(result.err, ErrRegisteredDeviceLimit) {
			t.Fatal(result.err)
		}
	}
	if len(accepted) != 2 {
		t.Fatalf("concurrent registration admitted %d, expected2", len(accepted))
	}
	value, err = p.RegisteredDevices(ctx, client.ID)
	check(err)
	if value.Count != 2 {
		t.Fatal("registry count differs")
	}
	for _, d := range value.Devices {
		if len(d.IdentifierHint) > 12 || strings.Contains(d.IdentifierHint, "synthetic") {
			t.Fatal("full HWID leaked to display")
		}
	}
	_, err = p.AdmitSubscriptionDevice(ctx, client.ID, proof, &subscriptioncompat.DeviceObservation{HWID: accepted[0]}, false)
	check(err)
	_, err = p.SetRegisteredDeviceLimit(ctx, client.ID, 1)
	if !errors.Is(err, ErrRegisteredDevicesTooMany) {
		t.Fatal("lowering limit must not evict random devices")
	}
	if _, err = p.DeleteRegisteredDevice(foreignCtx, client.ID, value.Devices[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign device delete allowed")
	}
	_, err = p.DeleteRegisteredDevice(ctx, client.ID, value.Devices[0].ID)
	check(err)
	_, err = p.AdmitSubscriptionDevice(ctx, client.ID, proof, &subscriptioncompat.DeviceObservation{HWID: "replacement-device"}, false)
	check(err)
	value, err = p.RegisteredDevices(ctx, client.ID)
	check(err)
	if value.Count != 2 {
		t.Fatal("deletion did not free exactly one slot")
	}
	// Metadata/HEAD inspection never registers a third device.
	_, err = p.AdmitSubscriptionDevice(ctx, client.ID, proof, &subscriptioncompat.DeviceObservation{HWID: "head-only-device"}, true)
	check(err)
	value, err = p.RegisteredDevices(ctx, client.ID)
	check(err)
	if value.Count != 2 {
		t.Fatal("read-only check registered a device")
	}
	// A previously resolved token cannot register after rotation/revocation.
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_client_subscriptions SET token_version=2 WHERE client_id=$1::uuid`, client.ID)
	check(err)
	_, err = p.AdmitSubscriptionDevice(ctx, client.ID, proof, &subscriptioncompat.DeviceObservation{HWID: accepted[0]}, false)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("stale subscription proof admitted")
	}
	proof.TokenVersion = 2
	_, err = p.SetRegisteredDeviceLimit(ctx, client.ID, 0)
	check(err)
	_, err = p.AdmitSubscriptionDevice(ctx, client.ID, proof, nil, false)
	check(err)
	value, err = p.RegisteredDevices(ctx, client.ID)
	check(err)
	if value.Count != 2 || value.Limit != 0 {
		t.Fatal("disabling limit changed existing devices")
	}
}
