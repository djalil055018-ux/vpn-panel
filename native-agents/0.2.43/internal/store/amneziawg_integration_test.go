//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestAmneziaWGPlatformDialectsIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(180*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("database unavailable")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, err := p.CreateTenant(ctx, "AWG isolated dialect integration")
	check(err)
	release, created, err := p.ImportReviewedAmneziaWG(ctx)
	check(err)
	if !created || release.Approved {
		t.Fatal("import implicitly approved runtime")
	}
	bootstrap := security.HashToken("synthetic-awg-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "AWG synthetic node", bootstrap, "amneziawg")
	check(err)
	if _, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-awg-agent"), "0.2.41", "ubuntu", "24.04", "amd64", "amneziawg"); err == nil {
		t.Fatal("old agent accepted")
	}
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-awg-agent"), "0.2.42", "ubuntu", "24.04", "amd64", "amneziawg")
	check(err)
	if _, _, err = p.InitializeAmneziaWGRuntime(ctx, node.ID); !errors.Is(err, ErrPinnedCoreReleaseUnavailable) {
		t.Fatal("unapproved runtime initialized")
	}
	check(p.ApproveReviewedAmneziaWG(ctx))
	initial, changed, err := p.InitializeAmneziaWGRuntime(ctx, node.ID)
	check(err)
	if !changed || initial.Generation != 1 || initial.Core.Type != "amneziawg" {
		t.Fatal("initialization")
	}
	_, changed, err = p.InitializeAmneziaWGRuntime(ctx, node.ID)
	check(err)
	if changed {
		t.Fatal("non-idempotent initialization")
	}
	address, port := "awg.example.test", 51820
	if _, err = p.CreateVPNService(ctx, node.ID, "foreign", "wireguard", "0.0.0.0", port, "udp", "wireguard", &address, &port); err == nil {
		t.Fatal("foreign runtime service accepted")
	}
	service, err := p.CreateVPNService(ctx, node.ID, "AWG", "amneziawg", "0.0.0.0", port, "udp", "amneziawg", &address, &port)
	check(err)
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true); !errors.Is(err, ErrAmneziaWGConfiguration) {
		t.Fatal("service enabled without dialect settings")
	}
	config, generation, err := p.ConfigureVPNServiceAmneziaWG(ctx, service.ID, "1.0")
	check(err)
	if config.Version != "1.0" || generation != 0 {
		t.Fatal("disabled configuration rebuilt node")
	}
	_, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(err)
	second, err := p.CreateVPNService(ctx, node.ID, "second", "amneziawg", "0.0.0.0", port+1, "udp", "amneziawg", &address, &port)
	check(err)
	_, _, err = p.ConfigureVPNServiceAmneziaWG(ctx, second.ID, "1.0")
	check(err)
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, second.ID, true); err == nil {
		t.Fatal("multiple enabled native AWG services accepted")
	}
	client, err := p.CreateVPNClient(ctx, tenant.ID, "synthetic AWG client", nil)
	check(err)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	desired := func() model.DesiredState {
		t.Helper()
		var raw []byte
		check(p.Pool.QueryRow(ctx, `SELECT d.document FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, node.ID).Scan(&raw))
		var state model.DesiredState
		check(json.Unmarshal(raw, &state))
		return state
	}
	first := desired()
	if len(first.Services) != 1 || len(first.Services[0].Clients) != 1 {
		t.Fatal("peer missing")
	}
	for _, version := range []string{"1.0", "1.5", "2.0", "3.0", "3.1"} {
		t.Run(version, func(t *testing.T) {
			_, _, e := p.ConfigureVPNServiceAmneziaWG(ctx, service.ID, version)
			check(e)
			state := desired()
			if state.Core.Type != "amneziawg" || state.Services[0].AmneziaWG.Version != version || state.Services[0].WireGuard.PrivateKey != first.Services[0].WireGuard.PrivateKey || *state.Services[0].Clients[0].WireGuard != *first.Services[0].Clients[0].WireGuard {
				t.Fatal("dialect changed peer identity")
			}
			connections, e := p.ListVPNClientConnections(ctx, client.ID)
			check(e)
			if len(connections) != 1 || connections[0].Protocol != "amneziawg" || connections[0].AmneziaWGVersion != version || connections[0].Config == "" || !strings.Contains(connections[0].Config, "Jc = ") {
				t.Fatal("AWG file missing or wrong dialect")
			}
			_, gen, e := p.ConfigureVPNServiceAmneziaWG(ctx, service.ID, version)
			check(e)
			if gen != 0 || desired().Generation != state.Generation {
				t.Fatal("identical dialect regenerated settings")
			}
		})
	}
	last := desired()
	raw, err := json.Marshal(last)
	check(err)
	var forged model.DesiredState
	check(json.Unmarshal(raw, &forged))
	forged.Generation++
	forged.Services[0].AmneziaWG.S1++
	if p.SaveDesiredState(ctx, node.ID, forged, release.ID) == nil {
		t.Fatal("unowned obfuscation settings accepted")
	}
	if desired().Generation != last.Generation {
		t.Fatal("rejected state changed generation")
	}
	if _, _, err = p.ConfigureVPNServiceAmneziaWG(ctx, service.ID, "9.0"); !errors.Is(err, ErrAmneziaWGConfiguration) {
		t.Fatal("unsupported dialect accepted")
	}
	other, err := p.CreateTenant(ctx, "AWG foreign synthetic tenant")
	check(err)
	foreign := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: other.ID})
	if _, err = p.GetVPNServiceAmneziaWG(foreign, service.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign tenant read configuration")
	}
	if _, _, err = p.ConfigureVPNServiceAmneziaWG(foreign, service.ID, "1.0"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign tenant changed configuration")
	}
	_, err = p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	if len(desired().Services[0].Clients) != 0 {
		t.Fatal("revoked peer remains in desired state")
	}
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if len(connections) != 0 {
		t.Fatal("revoked profile still available")
	}
}
