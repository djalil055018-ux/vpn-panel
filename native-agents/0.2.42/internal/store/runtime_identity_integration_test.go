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
	"vpn-platform/internal/security"
)

func TestNodeRuntimeIdentityIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(60*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("clone connection failed")
	}
	defer p.Close()
	var database string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || !strings.HasPrefix(database, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "CODEX-RUNTIME-IDENTITY")
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
	xray, err := p.CreateNode(ctx, tenant.ID, "CODEX-RUNTIME-XRAY", security.HashToken("fixture-bootstrap-x"))
	check(err)
	bootstrap := security.HashToken("fixture-bootstrap-h")
	hysteria, err := p.CreateNodeForRuntime(ctx, tenant.ID, "CODEX-RUNTIME-HYS", bootstrap, "hysteria2")
	check(err)
	if xray.RuntimeCore != "xray" || hysteria.RuntimeCore != "hysteria2" {
		t.Fatal("created node selection missing")
	}
	for _, nodeID := range []string{xray.ID, hysteria.ID} {
		if _, _, e := p.InitializeHysteriaRuntime(ctx, nodeID); !errors.Is(e, ErrNodeRuntime) {
			t.Fatal("unregistered or Xray node initialized as Hysteria")
		}
	}
	for _, pair := range [][2]string{{xray.ID, "hysteria2"}, {hysteria.ID, "xray"}} {
		if _, e := p.GetCoreUpdateStatus(ctx, pair[0], pair[1]); !errors.Is(e, ErrNodeRuntime) {
			t.Fatal("cross-runtime update status accepted")
		}
		if _, e := p.EvaluateCoreUpdate(ctx, pair[0], pair[1], "2.12.2"); !errors.Is(e, ErrNodeRuntime) {
			t.Fatal("cross-runtime update evaluation accepted")
		}
		if _, _, e := p.SetCoreUpdatePolicy(ctx, pair[0], pair[1], "stable", ""); !errors.Is(e, ErrNodeRuntime) {
			t.Fatal("cross-runtime update policy accepted")
		}
		if _, e := p.CreateCoreRolloutPlan(ctx, pair[0], pair[1]); !errors.Is(e, ErrNodeRuntime) {
			t.Fatal("cross-runtime rollout preview accepted")
		}
	}
	if _, err = p.CreateNodeForRuntime(ctx, tenant.ID, "invalid", bootstrap, "unknown"); !errors.Is(err, ErrNodeRuntime) {
		t.Fatal("unknown runtime accepted")
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE nodes SET runtime_core='hysteria2' WHERE id=$1::uuid`, xray.ID); err == nil {
		t.Fatal("existing Xray node migrated")
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE nodes SET runtime_core='xray' WHERE id=$1::uuid`, hysteria.ID); err == nil {
		t.Fatal("Hysteria node migrated")
	}
	token := security.HashToken("fixture-permanent-h")
	if _, err = p.BootstrapAgent(ctx, bootstrap, token, "0.2.25", "ubuntu", "24.04", "amd64"); !errors.Is(err, ErrNotFound) {
		t.Fatal("legacy Xray registration claimed a Hysteria node")
	}
	if _, err = p.BootstrapAgentForRuntime(ctx, bootstrap, token, "0.2.23", "ubuntu", "24.04", "amd64", "hysteria2"); !errors.Is(err, ErrNodeRuntime) {
		t.Fatal("old agent claimed a Hysteria node")
	}
	var consumed bool
	check(p.Pool.QueryRow(ctx, `SELECT bootstrap_used_at IS NOT NULL FROM nodes WHERE id=$1::uuid`, hysteria.ID).Scan(&consumed))
	if consumed {
		t.Fatal("rejected registration consumed bootstrap")
	}
	registered, err := p.BootstrapAgentForRuntime(ctx, bootstrap, token, "0.2.25", "ubuntu", "24.04", "amd64", "hysteria2")
	check(err)
	if registered.RuntimeCore != "hysteria2" {
		t.Fatal("registration lost runtime")
	}
	authenticated, err := p.NodeByAgentToken(ctx, token)
	check(err)
	if authenticated.RuntimeCore != "hysteria2" {
		t.Fatal("authentication lost runtime")
	}
	lifecycle, err := p.NodeLifecycle(ctx, hysteria.ID, time.Now())
	check(err)
	if lifecycle.RuntimeCore != "hysteria2" {
		t.Fatal("self status lost runtime")
	}
	for _, report := range []model.HealthReport{{Core: "xray", AgentVersion: "0.2.25"}, {Core: "hysteria2", AgentVersion: "0.2.23"}, {AgentVersion: "0.2.25"}} {
		report.CheckedAt = time.Now()
		if err = p.SaveHealth(ctx, hysteria.ID, report); !errors.Is(err, ErrNodeRuntime) {
			t.Fatal("incompatible health report accepted")
		}
	}
	var healthRows int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM node_health WHERE node_id=$1::uuid`, hysteria.ID).Scan(&healthRows))
	if healthRows != 0 {
		t.Fatal("rejected health changed observations")
	}
	check(p.SaveHealth(ctx, hysteria.ID, model.HealthReport{Core: "hysteria2", AgentVersion: "0.2.25", CheckedAt: time.Now()}))
	nodes, err := p.ListNodes(ctx)
	check(err)
	found := false
	for _, node := range nodes {
		if node.ID == hysteria.ID {
			found = node.RuntimeCore == "hysteria2"
		}
	}
	if !found {
		t.Fatal("node list lost runtime")
	}
	if _, err = p.BootstrapAgentForRuntime(ctx, bootstrap, token, "0.2.25", "ubuntu", "24.04", "amd64", "hysteria2"); !errors.Is(err, ErrNotFound) {
		t.Fatal("bootstrap replay accepted")
	}
	// Guard direct SQL too: old application code cannot cross selected cores.
	for _, pair := range [][2]string{{xray.ID, "hysteria2"}, {hysteria.ID, "xray"}} {
		if _, err = p.Pool.Exec(ctx, `INSERT INTO desired_states(node_id,generation,document) VALUES($1::uuid,1,jsonb_build_object('generation',1,'core',jsonb_build_object('type',$2::text)))`, pair[0], pair[1]); err == nil {
			t.Fatal("cross-core desired state accepted")
		}
	}
	for _, cfg := range []struct{ node, protocol, transport, security string }{{xray.ID, "hysteria2", "udp", "tls"}, {hysteria.ID, "vless", "tcp", "tls"}, {hysteria.ID, "hysteria2", "tcp", "tls"}, {hysteria.ID, "hysteria2", "udp", "reality"}} {
		if _, err = p.CreateVPNService(ctx, cfg.node, "invalid", cfg.protocol, "127.0.0.1", 443, cfg.transport, cfg.security, nil, nil); err == nil {
			t.Fatal("incompatible service accepted")
		}
	}
	first, err := p.CreateVPNService(ctx, hysteria.ID, "first", "hysteria2", "127.0.0.1", 443, "udp", "tls", nil, nil)
	check(err)
	second, err := p.CreateVPNService(ctx, hysteria.ID, "second", "hysteria2", "127.0.0.1", 444, "udp", "tls", nil, nil)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_services SET enabled=true WHERE id=$1::uuid`, first.ID)
	check(err)
	if _, err = p.Pool.Exec(ctx, `UPDATE vpn_services SET enabled=true WHERE id=$1::uuid`, second.ID); err == nil {
		t.Fatal("second Hysteria listener enabled")
	}
}
