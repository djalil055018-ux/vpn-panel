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

func TestPPTPPlatformIntegration(t *testing.T) {
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
	tenant, err := p.CreateTenant(ctx, "PPTP integration")
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
	release, _, err := p.ImportReviewedPPTP(ctx)
	check(err)
	releaseID = release.ID
	bootstrap := security.HashToken("pptp-fixture-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "PPTP test", bootstrap, "pptp")
	check(err)
	if _, _, err = p.InitializePPTPRuntime(ctx, node.ID); err == nil {
		t.Fatal("unregistered node initialized")
	}
	if _, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("pptp-agent"), "0.2.29", "ubuntu", "24.04", "amd64", "pptp"); err == nil {
		t.Fatal("old Agent accepted PPTP")
	}
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("pptp-agent"), "0.2.30", "ubuntu", "24.04", "amd64", "pptp")
	check(err)
	if _, _, err = p.InitializePPTPRuntime(ctx, node.ID); err == nil {
		t.Fatal("unapproved runtime initialized")
	}
	check(p.ApproveReviewedPPTP(ctx))
	initial, changed, err := p.InitializePPTPRuntime(ctx, node.ID)
	check(err)
	if !changed || initial.Generation != 1 {
		t.Fatal("initial generation missing")
	}
	_, changed, err = p.InitializePPTPRuntime(ctx, node.ID)
	check(err)
	if changed {
		t.Fatal("initialization not idempotent")
	}
	address, port := "pptp.example.test", 1723
	if _, err = p.CreateVPNService(ctx, node.ID, "foreign", "vless", "0.0.0.0", port, "tcp", "reality", &address, &port); err == nil {
		t.Fatal("foreign protocol accepted")
	}
	if _, err = p.CreateVPNService(ctx, node.ID, "wrong transport", "pptp", "0.0.0.0", port, "tcp", "mppe", &address, &port); err == nil {
		t.Fatal("missing GRE accepted")
	}
	service, err := p.CreateVPNService(ctx, node.ID, "PPTP", "pptp", "0.0.0.0", port, "tcp,gre", "mppe", &address, &port)
	check(err)
	_, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(err)
	second, err := p.CreateVPNService(ctx, node.ID, "second", "pptp", "127.0.0.1", port, "tcp,gre", "mppe", &address, &port)
	check(err)
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, second.ID, true); err == nil {
		t.Fatal("two PPTP services enabled")
	}
	client, err := p.CreateVPNClient(ctx, tenant.ID, "PPTP client", nil)
	check(err)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	desired := func(count int) model.DesiredState {
		t.Helper()
		var raw []byte
		check(p.Pool.QueryRow(ctx, `SELECT d.document FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, node.ID).Scan(&raw))
		var state model.DesiredState
		check(json.Unmarshal(raw, &state))
		if len(state.Services) != 1 || state.Core.Type != "pptp" || len(state.Services[0].Clients) != count {
			t.Fatalf("desired access differs: services=%d", len(state.Services))
		}
		connections, e := p.ListVPNClientConnections(ctx, client.ID)
		check(e)
		if len(connections) != count {
			t.Fatalf("delivered access differs: %d != %d", len(connections), count)
		}
		if count == 1 {
			c := connections[0]
			peer := state.Services[0].Clients[0]
			if c.Protocol != "pptp" || c.Username != client.ID || c.Password != peer.PPTP.Password || c.Password == client.VLESSUUID || !strings.Contains(c.Config, "MS-CHAPv2") || c.URI != "" || !strings.HasSuffix(c.ConfigFilename, ".pptp.txt") {
				t.Fatal("PPTP credential delivery differs")
			}
		}
		return state
	}
	state := desired(1)
	originalPassword := state.Services[0].Clients[0].PPTP.Password
	originalAddress := state.Services[0].Clients[0].PPTP.Address
	_, err = p.RebuildNodeDesiredState(ctx, node.ID)
	check(err)
	state = desired(1)
	if state.Services[0].Clients[0].PPTP.Password != originalPassword {
		t.Fatal("routine rebuild changed password")
	}
	for name, mutate := range map[string]func(*model.DesiredState){
		"unreviewed release": func(s *model.DesiredState) { s.Core.SHA256 = strings.Repeat("a", 64) },
		"foreign password":   func(s *model.DesiredState) { s.Services[0].Clients[0].PPTP.Password = strings.Repeat("b", 64) },
		"foreign route":      func(s *model.DesiredState) { s.Services[0].Clients[0].PPTP.Address = "10.78.0.253" },
		"traffic identity": func(s *model.DesiredState) {
			s.Services[0].Clients[0].StatsKey = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"disabled service": func(s *model.DesiredState) { s.Services[0].ID = second.ID },
		"foreign runtime":  func(s *model.DesiredState) { s.Core.Type = "xray" },
		"duplicate client": func(s *model.DesiredState) {
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
			if p.SaveDesiredState(ctx, node.ID, attack, release.ID) == nil {
				t.Fatal("unowned desired configuration accepted")
			}
			if desired(1).Generation != state.Generation {
				t.Fatal("rejected write changed generation")
			}
		})
	}
	_, err = p.RotatePPTPClientCredential(ctx, service.ID, client.ID)
	check(err)
	rotated := desired(1)
	if rotated.Services[0].Clients[0].PPTP.Password == originalPassword || rotated.Services[0].Clients[0].PPTP.Address != originalAddress {
		t.Fatal("rotation did not replace only the password")
	}
	_, err = p.SetVPNClientStatus(ctx, client.ID, "disabled")
	check(err)
	desired(0)
	forged := state
	forged.Generation = rotated.Generation + 2
	if p.SaveDesiredState(ctx, node.ID, forged, release.ID) == nil {
		t.Fatal("disabled credential restored by raw desired")
	}
	_, err = p.SetVPNClientStatus(ctx, client.ID, "active")
	check(err)
	desired(1)
	expired := time.Now().Add(-time.Minute)
	_, err = p.UpdateVPNClient(ctx, client.ID, nil, nil, &expired, true)
	check(err)
	desired(0)
	_, err = p.UpdateVPNClient(ctx, client.ID, nil, nil, nil, true)
	check(err)
	desired(1)
	// Persist an actual ordered traffic sample, cross quota, then restore access
	// by increasing the quota while preserving the usage cursor.
	_, err = p.SetVPNClientLimits(ctx, client.ID, 100, 1)
	check(err)
	tx, err := p.Pool.Begin(ctx)
	check(err)
	defer tx.Rollback(context.Background())
	crossed, err := saveClientTraffic(ctx, tx, node.ID, []model.ClientTraffic{{ClientID: client.ID, Uplink: 60, Downlink: 50, ActiveIPsUnavailable: true}}, time.Now().UTC(), strings.Repeat("a", 32), 1)
	check(err)
	check(tx.Commit(ctx))
	if len(crossed) != 1 {
		t.Fatal("traffic did not cross quota")
	}
	_, err = p.ReconcileInactiveVPNClients(ctx)
	check(err)
	desired(0)
	_, err = p.SetVPNClientLimits(ctx, client.ID, 200, 1)
	check(err)
	desired(1)
	n, err := p.ReconcileInactiveVPNClients(ctx)
	check(err)
	if n != 0 {
		t.Fatal("steady active access keeps rebuilding")
	}
	plan, err := p.CreateVPNAccessPlan(ctx, tenant.ID, "PPTP plan", "pptp-plan", true)
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
	// Reattaching restores the rotated password, never the old one.
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	last := desired(1)
	if last.Services[0].Clients[0].PPTP.Password != rotated.Services[0].Clients[0].PPTP.Password {
		t.Fatal("reassignment changed or resurrected credential")
	}
	assertNativeContinuousQuota(t, p, ctx, client.ID, func(n int) { desired(n) })
}
