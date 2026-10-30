//go:build integration

package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestNativeWireGuardPlatformIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(90*time.Second))
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
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "Native WireGuard integration")
	check(err)
	var releaseID string
	defer func() {
		_, e := p.Pool.Exec(context.Background(), `DELETE FROM vpn_services WHERE tenant_id=$1::uuid`, tenant.ID)
		check(e)
		_, e = p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
		check(e)
		if releaseID != "" {
			_, e = p.Pool.Exec(context.Background(), `DELETE FROM core_releases WHERE id=$1::uuid`, releaseID)
			check(e)
		}
	}()
	release, _, err := p.ImportReviewedNativeWireGuard(ctx)
	check(err)
	releaseID = release.ID
	check(p.ApproveReviewedNativeWireGuard(ctx))
	bootstrap := security.HashToken("native-wg-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "Native WireGuard", bootstrap, "wireguard")
	check(err)
	if _, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("native-wg-agent"), "0.2.27", "ubuntu", "24.04", "amd64", "wireguard"); err == nil {
		t.Fatal("old Agent accepted native node")
	}
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("native-wg-agent"), "0.2.28", "ubuntu", "24.04", "amd64", "wireguard")
	check(err)
	initial, changed, err := p.InitializeNativeWireGuardRuntime(ctx, node.ID)
	check(err)
	if !changed || initial.Generation != 1 {
		t.Fatal("initialization")
	}
	_, changed, err = p.InitializeNativeWireGuardRuntime(ctx, node.ID)
	check(err)
	if changed {
		t.Fatal("initialization was not idempotent")
	}
	address, port := "wg.example.test", 51820
	if _, err = p.CreateVPNService(ctx, node.ID, "foreign", "vless", "0.0.0.0", port, "tcp", "reality", &address, &port); err == nil {
		t.Fatal("native node accepted foreign service")
	}
	service, err := p.CreateVPNService(ctx, node.ID, "native", "wireguard", "0.0.0.0", port, "udp", "wireguard", &address, &port)
	check(err)
	_, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(err)
	second, err := p.CreateVPNService(ctx, node.ID, "second", "wireguard", "0.0.0.0", port+1, "udp", "wireguard", &address, &port)
	check(err)
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, second.ID, true); err == nil {
		t.Fatal("multiple native services enabled")
	}
	client, err := p.CreateVPNClient(ctx, tenant.ID, "native client", nil)
	check(err)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	desired := func(count int) model.DesiredState {
		t.Helper()
		var raw []byte
		check(p.Pool.QueryRow(ctx, `SELECT d.document FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, node.ID).Scan(&raw))
		var s model.DesiredState
		check(json.Unmarshal(raw, &s))
		if s.Core.Type != "wireguard" || len(s.Services) != 1 || len(s.Services[0].Clients) != count {
			t.Fatal("native desired access differs")
		}
		return s
	}
	state := desired(1)
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if len(connections) != 1 || connections[0].RuntimeCore != "wireguard" || !strings.Contains(connections[0].Config, "[Peer]") {
		t.Fatal("native profile missing")
	}
	for name, mutate := range map[string]func(*model.DesiredState){
		"server key not owned": func(s *model.DesiredState) {
			s.Services[0].WireGuard.PrivateKey = s.Services[0].Clients[0].WireGuard.PresharedKey
		},
		"peer key not owned": func(s *model.DesiredState) {
			s.Services[0].Clients[0].WireGuard.PublicKey = s.Services[0].WireGuard.PrivateKey
		},
		"peer preshared key not owned": func(s *model.DesiredState) {
			s.Services[0].Clients[0].WireGuard.PresharedKey = s.Services[0].WireGuard.PrivateKey
		},
		"peer route not owned":          func(s *model.DesiredState) { s.Services[0].Clients[0].WireGuard.Address = "10.66.255.254/32" },
		"disabled service substitution": func(s *model.DesiredState) { s.Services[0].ID = second.ID },
		"unreviewed tools URL":          func(s *model.DesiredState) { s.Core.DownloadURL = "https://unreviewed.invalid/wg.deb" },
		"unreviewed tools checksum":     func(s *model.DesiredState) { s.Core.SHA256 = strings.Repeat("a", 64) },
		"foreign runtime":               func(s *model.DesiredState) { s.Core.Type = "xray" },
		"duplicate peer identity": func(s *model.DesiredState) {
			s.Services[0].Clients = append(s.Services[0].Clients, s.Services[0].Clients[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, e := json.Marshal(state)
			check(e)
			var attack model.DesiredState
			check(json.Unmarshal(raw, &attack))
			attack.Generation++
			mutate(&attack)
			if p.SaveDesiredState(ctx, node.ID, attack, releaseID) == nil {
				t.Fatal("unowned native configuration accepted")
			}
			if desired(1).Generation != state.Generation {
				t.Fatal("rejected configuration changed the desired generation")
			}
		})
	}
	forged := state
	forged.Generation++
	forged.Services = append([]model.ServiceSpec(nil), state.Services...)
	forged.Services[0].Clients = append([]model.ClientSpec(nil), state.Services[0].Clients...)
	forged.Services[0].Clients[0].StatsKey = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if p.SaveDesiredState(ctx, node.ID, forged, releaseID) == nil {
		t.Fatal("foreign traffic identity accepted")
	}
	desired(1)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()-interval '1 minute' WHERE id=$1::uuid`, client.ID)
	check(err)
	expired := state
	expired.Generation++
	if p.SaveDesiredState(ctx, node.ID, expired, releaseID) == nil {
		t.Fatal("raw desired state restored an expired native peer")
	}
	n, err := p.ReconcileInactiveVPNClients(ctx)
	check(err)
	if n != 1 {
		t.Fatal("native expiry missed")
	}
	desired(0)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=NULL WHERE id=$1::uuid`, client.ID)
	check(err)
	n, err = p.ReconcileInactiveVPNClients(ctx)
	check(err)
	if n != 1 {
		t.Fatal("native expiry restoration missed")
	}
	desired(1)
	n, err = p.ReconcileInactiveVPNClients(ctx)
	check(err)
	if n != 0 {
		t.Fatal("native steady state keeps rebuilding")
	}
	assertNativeContinuousQuota(t, p, ctx, client.ID, func(n int) { desired(n) })
	plan, err := p.CreateVPNAccessPlan(ctx, tenant.ID, "native plan", "native-wg-plan", true)
	check(err)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service.ID, true)
	check(err)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	_, err = p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	desired(1)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, false)
	check(err)
	desired(0)
}
