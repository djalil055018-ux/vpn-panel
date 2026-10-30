//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/subscriptioncompat"
)

func TestCascadeDialPolicyIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(90*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("isolated database unavailable")
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
		t.Fatal("refusing production database")
	}
	tenant, services := nativeAccessFixture(t, ctx, p)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.34' WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	plan, err := p.CreateVPNAccessPlan(ctx, tenant, "Dial policy test", "dial-policy-test", true)
	check(err)
	input := model.VPNCascadeInput{Name: "Dial policy", PlanID: plan.ID, EntryServiceID: services[0], ExitServiceID: services[1], EntryPort: 9443, Enabled: true}
	initial, err := p.PutVPNCascade(ctx, tenant, "", input)
	check(err)
	id := initial.Cascade.ID
	sum := func() int64 {
		var n int64
		check(p.Pool.QueryRow(ctx, `SELECT sum(desired_generation) FROM nodes WHERE tenant_id=$1::uuid`, tenant).Scan(&n))
		return n
	}
	ip, attempts := "192.0.2.10", 16
	input.ConnectRaceIP = &ip
	input.ConnectRaceAttempts = &attempts
	before := sum()
	_, err = p.PutVPNCascade(ctx, tenant, id, input)
	if !errors.Is(err, ErrNodeRuntime) || sum() != before {
		t.Fatal("old agent accepted or partial mutation committed")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.44' WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	clientDial := true
	input.ConnectRaceClients = &clientDial
	updated, err := p.PutVPNCascade(ctx, tenant, id, input)
	check(err)
	if !updated.Changed || len(updated.Rebuilds) != 2 || updated.Cascade.ConnectRaceAttempts != 16 {
		t.Fatal("policy did not atomically rebuild")
	}
	desired, ok, err := p.LatestDesiredState(ctx, updated.Cascade.EntryNodeID)
	check(err)
	if !ok || desired.XrayCascades == nil || len(desired.XrayCascades.Entries) != 1 || desired.XrayCascades.Entries[0].Exit.ConnectRaceIP != ip {
		t.Fatal("signed assignment missing explicit dial policy")
	}
	hosts := []subscriptioncompat.Host{{Name: "entry", Address: "first.example.test", Protocol: "vless", Transport: "tcp", Security: "reality"}, {Name: "exit", Address: "second.example.test", Protocol: "vless", Transport: "tcp", Security: "reality"}}
	publicHosts, e := p.ApplyClientCascadeDial(ctx, tenant, hosts, services)
	check(e)
	if publicHosts[0].ConnectRaceAttempts != 0 || publicHosts[1].ConnectRaceAttempts != 16 || hosts[1].ConnectRaceAttempts != 0 {
		t.Fatal("client dial policy crossed endpoints or mutated source metadata")
	}
	status, err := p.VPNCascadeStatus(ctx, id)
	check(err)
	if status.ConnectRaceAttempts != 16 {
		t.Fatal("status omitted policy")
	}
	listed, err := p.ListVPNCascades(ctx, tenant)
	check(err)
	if len(listed) != 1 || listed[0].ConnectRaceIP != ip {
		t.Fatal("public listing omitted policy")
	}
	// Older browser forms omit the additive fields. A rename must preserve them.
	input.ConnectRaceIP = nil
	input.ConnectRaceAttempts = nil
	input.ConnectRaceClients = nil
	input.Name = "Renamed policy"
	renamed, err := p.PutVPNCascade(ctx, tenant, id, input)
	check(err)
	if len(renamed.Rebuilds) != 0 || renamed.Cascade.ConnectRaceAttempts != 16 {
		t.Fatal("metadata update cleared policy or restarted VPN")
	}
	bad := 17
	input.ConnectRaceIP = &ip
	input.ConnectRaceAttempts = &bad
	before = sum()
	if _, err = p.PutVPNCascade(ctx, tenant, id, input); !errors.Is(err, ErrVPNCascade) || sum() != before {
		t.Fatal("invalid policy changed state")
	}
	input.ConnectRaceIP = nil
	if _, err = p.PutVPNCascade(ctx, tenant, id, input); !errors.Is(err, ErrVPNCascade) {
		t.Fatal("incomplete policy accepted")
	}
	// A node with an older agent can still disable an opted-in cascade safely.
	input.ConnectRaceAttempts = nil
	input.Enabled = false
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.40' WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	disabled, err := p.PutVPNCascade(ctx, tenant, id, input)
	check(err)
	if disabled.Cascade.Enabled || disabled.Cascade.ConnectRaceAttempts != 16 {
		t.Fatal("disable lost stored policy")
	}
	// Explicit empty values clear the policy; omission does not.
	ip = ""
	attempts = 0
	input.ConnectRaceIP = &ip
	input.ConnectRaceAttempts = &attempts
	cleared, err := p.PutVPNCascade(ctx, tenant, id, input)
	check(err)
	if cleared.Cascade.ConnectRaceIP != "" || cleared.Cascade.ConnectRaceAttempts != 0 {
		t.Fatal("explicit policy clear failed")
	}
	stale := initial.Cascade.UpdatedAt
	input.ExpectedUpdatedAt = &stale
	before = sum()
	if _, err = p.PutVPNCascade(ctx, tenant, id, input); !errors.Is(err, ErrVPNCascade) || sum() != before {
		t.Fatal("stale editor overwrote newer operator settings")
	}
	fresh := cleared.Cascade.UpdatedAt
	input.ExpectedUpdatedAt = &fresh
	if _, err = p.PutVPNCascade(ctx, tenant, id, input); err != nil {
		t.Fatal("exact editor version rejected")
	}
	// A later operator address edit wins over an older explicit dial pin and
	// reaches the cascade entry immediately, without waiting for another client.
	input.ExpectedUpdatedAt = nil
	pinIP, pinAttempts, pinClients := "192.0.2.10", 16, true
	input.ConnectRaceIP = &pinIP
	input.ConnectRaceAttempts = &pinAttempts
	input.ConnectRaceClients = &pinClients
	input.Enabled = true
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.44' WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	pinned, err := p.PutVPNCascade(ctx, tenant, id, input)
	check(err)
	oldEntry, _, err := p.LatestDesiredState(ctx, pinned.Cascade.EntryNodeID)
	check(err)
	exitService, err := p.GetVPNService(ctx, services[1])
	check(err)
	_, _, err = p.UpdateVPNServiceConfigurationAndRebuild(ctx, exitService.ID, exitService.Name, exitService.Listen, exitService.Port, exitService.Transport, "new-exit.example.test", *exitService.PublicPort)
	check(err)
	afterEdit, err := p.GetVPNCascade(ctx, id)
	check(err)
	if afterEdit.ConnectRaceIP != "" || afterEdit.ConnectRaceClients {
		t.Fatal("operator endpoint edit retained an older pin")
	}
	entryAfterEdit, _, err := p.LatestDesiredState(ctx, pinned.Cascade.EntryNodeID)
	check(err)
	if entryAfterEdit.Generation <= oldEntry.Generation || entryAfterEdit.XrayCascades.Entries[0].Exit.Address != "new-exit.example.test" || entryAfterEdit.XrayCascades.Entries[0].Exit.ConnectRaceAttempts != 0 {
		t.Fatal("entry did not follow newer endpoint settings")
	}
	// The old browser can also choose a different exit without carrying this pin.
	_, err = p.PutVPNCascade(ctx, tenant, id, input)
	check(err)
	input.EntryServiceID, input.ExitServiceID = services[1], services[0]
	input.ConnectRaceIP = nil
	input.ConnectRaceAttempts = nil
	input.ConnectRaceClients = nil
	swapped, err := p.PutVPNCascade(ctx, tenant, id, input)
	check(err)
	if swapped.Cascade.ConnectRaceAttempts != 0 || swapped.Cascade.ConnectRaceClients {
		t.Fatal("old editor carried a pin to a different exit")
	}

}
