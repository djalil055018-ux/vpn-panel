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

func TestWireGuardAccessIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
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
	var releaseID string
	tenant, err := p.CreateTenant(ctx, "VLESS integration")
	check(err)
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
	release, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.7.30", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/xray.zip", SHA256: strings.Repeat("a", 64), Channel: "testing"})
	check(err)
	releaseID = release.ID
	check(p.ApproveCoreRelease(ctx, release.ID))
	bootstrap := security.HashToken("vless-fixture-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "VLESS integration", bootstrap, "xray")
	check(err)
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("vless-fixture-agent"), "0.2.25", "ubuntu", "24.04", "amd64", "xray")
	check(err)
	initial := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: release.Type, Version: release.Version, DownloadURL: release.DownloadURL, SHA256: release.SHA256, Channel: release.Channel}}
	check(p.SaveDesiredState(ctx, node.ID, initial, release.ID))
	rawAttempt := initial
	rawAttempt.Generation = 2
	rawAttempt.Services = []model.ServiceSpec{{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Protocol: "wireguard", Transport: "udp", Security: "wireguard", WireGuard: &model.WireGuardSpec{PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}
	if p.SaveDesiredState(ctx, node.ID, rawAttempt, release.ID) == nil {
		t.Fatal("raw desired state bypassed Agent compatibility")
	}
	address, port := "vmess.example.test", 18444
	service, err := p.CreateVPNService(ctx, node.ID, "VLESS TLS", "wireguard", "127.0.0.1", port, "udp", "wireguard", &address, &port)
	check(err)
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true); err == nil {
		t.Fatal("old Agent accepted VLESS")
	}
	var enabled bool
	var generation int64
	check(p.Pool.QueryRow(ctx, `SELECT enabled FROM vpn_services WHERE id=$1::uuid`, service.ID).Scan(&enabled))
	check(p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, node.ID).Scan(&generation))
	if enabled || generation != 1 {
		t.Fatal("failed compatibility check changed service or generation")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.26' WHERE id=$1::uuid`, node.ID)
	check(err)
	_, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "VLESS client", nil)
	check(err)
	assertAccess := func(count int) {
		t.Helper()
		connections, e := p.ListVPNClientConnections(ctx, client.ID)
		if e == nil && len(connections) > 0 && connections[0].RuntimeCore != "xray" {
			t.Fatal("Xray runtime missing from export")
		}
		check(e)
		if len(connections) != count {
			t.Fatalf("connections=%d want %d", len(connections), count)
		}
		var raw []byte
		check(p.Pool.QueryRow(ctx, `SELECT d.document FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, node.ID).Scan(&raw))
		var state model.DesiredState
		check(json.Unmarshal(raw, &state))
		if len(state.Services) != 1 || state.Services[0].Protocol != "wireguard" || len(state.Services[0].Clients) != count {
			t.Fatal("desired state differs from effective access")
		}
		if count == 1 && state.Services[0].Clients[0].StatsKey != client.ID {
			t.Fatal("traffic identity lost")
		}
	}
	assertAccess(0)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertAccess(1)
	plan, err := p.CreateVPNAccessPlan(ctx, tenant.ID, "VLESS plan", "vmess-plan", true)
	check(err)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service.ID, true)
	check(err)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	_, err = p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertAccess(1)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, false)
	check(err)
	assertAccess(0)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertNativeContinuousQuota(t, p, ctx, client.ID, assertAccess)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.25' WHERE id=$1::uuid`, node.ID)
	check(err)
	if _, err = p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID); err == nil {
		t.Fatal("incompatible rebuild accepted")
	}
	assertAccess(1)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.26' WHERE id=$1::uuid`, node.ID)
	check(err)
	_, err = p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertAccess(0)
}
