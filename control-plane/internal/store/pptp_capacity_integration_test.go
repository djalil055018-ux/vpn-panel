//go:build integration

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestPPTPCapacityAtomicIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(120*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("isolated database unavailable")
	}
	defer p.Close()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var db string
	check(p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&db))
	if !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	tenant, err := p.CreateTenant(ctx, "PPTP capacity isolated")
	check(err)
	defer func() {
		cleanup := context.Background()
		_, e := p.Pool.Exec(cleanup, `DELETE FROM vpn_services WHERE tenant_id=$1::uuid`, tenant.ID)
		check(e)
		_, e = p.Pool.Exec(cleanup, `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
		check(e)
	}()
	_, _, err = p.ImportReviewedPPTP(ctx)
	check(err)
	check(p.ApproveReviewedPPTP(ctx))
	bootstrap := security.HashToken("capacity-" + tenant.ID)
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "PPTP capacity", bootstrap, "pptp")
	check(err)
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("agent-"+tenant.ID), "0.2.30", "ubuntu", "24.04", "amd64", "pptp")
	check(err)
	_, _, err = p.InitializePPTPRuntime(ctx, node.ID)
	check(err)
	address, port := "pptp-capacity.example.test", 1723
	service, err := p.CreateVPNService(ctx, node.ID, "Capacity", "pptp", "0.0.0.0", port, "tcp,gre", "mppe", &address, &port)
	check(err)
	_, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(err)
	// Seed 251 memberships in one transaction, then exercise the real rebuild and
	// concurrent public attachment methods around the remaining slot.
	_, err = p.Pool.Exec(ctx, `WITH created AS (INSERT INTO vpn_clients(tenant_id,name) SELECT $1::uuid,'capacity-'||x FROM generate_series(1,251) x RETURNING id,tenant_id) INSERT INTO vpn_client_services(tenant_id,client_id,service_id) SELECT tenant_id,id,$2::uuid FROM created`, tenant.ID, service.ID)
	check(err)
	initial, err := p.RebuildNodeDesiredState(ctx, node.ID)
	check(err)
	peers := func(state model.DesiredState) map[string]model.PPTPPeer {
		t.Helper()
		if len(state.Services) != 1 {
			t.Fatal("unexpected services")
		}
		result := map[string]model.PPTPPeer{}
		addresses := map[string]bool{}
		passwords := map[string]bool{}
		for _, c := range state.Services[0].Clients {
			if c.PPTP == nil || addresses[c.PPTP.Address] || passwords[c.PPTP.Password] || len(c.PPTP.Password) != 64 {
				t.Fatal("PPTP allocation collision")
			}
			result[c.StatsKey] = *c.PPTP
			addresses[c.PPTP.Address] = true
			passwords[c.PPTP.Password] = true
		}
		return result
	}
	originals := peers(initial)
	if len(originals) != 251 {
		t.Fatal("seed allocation count")
	}
	contenders := make([]model.VPNClient, 2)
	for i := range contenders {
		contenders[i], err = p.CreateVPNClient(ctx, tenant.ID, fmt.Sprintf("contender-%d", i), nil)
		check(err)
	}
	var wg sync.WaitGroup
	results := make([]error, 2)
	start := make(chan struct{})
	for i := range contenders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, results[i] = p.AttachVPNClientAndRebuild(ctx, service.ID, contenders[i].ID)
		}(i)
	}
	close(start)
	wg.Wait()
	winner, loser := -1, -1
	for i, e := range results {
		if e == nil {
			if winner != -1 {
				t.Fatal("overallocated last slot")
			}
			winner = i
		} else if errors.Is(e, ErrPPTPCapacity) {
			loser = i
		} else {
			t.Fatalf("unexpected attachment error: %v", e)
		}
	}
	if winner < 0 || loser < 0 {
		t.Fatal("last slot did not have one winner and one capacity rejection")
	}
	var generation int64
	check(p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, node.ID).Scan(&generation))
	if generation != initial.Generation+1 {
		t.Fatal("failed attachment changed generation")
	}
	var bindings, memberships int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_pptp WHERE service_id=$1::uuid`, service.ID).Scan(&bindings))
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_services WHERE service_id=$1::uuid`, service.ID).Scan(&memberships))
	if bindings != 252 || memberships != 252 {
		t.Fatal("failed attachment left partial rows")
	}
	connections, e := p.ListVPNClientConnections(ctx, contenders[loser].ID)
	check(e)
	if len(connections) != 0 {
		t.Fatal("rejected client received access")
	}
	stable, err := p.RebuildNodeDesiredState(ctx, node.ID)
	check(err)
	all := peers(stable)
	if len(all) != 252 {
		t.Fatal("full allocation count")
	}
	for id, peer := range originals {
		if all[id] != peer {
			t.Fatal("existing credential or address changed")
		}
	}
	seen := map[string]bool{}
	for _, peer := range all {
		seen[peer.Address] = true
	}
	for i := 2; i <= 253; i++ {
		if !seen[fmt.Sprintf("10.78.0.%d", i)] {
			t.Fatal("address range differs")
		}
	}
	// Detaching preserves the binding and its independently generated password.
	// Reattach must work at capacity without obtaining a second slot.
	_, err = p.DetachVPNClientAndRebuild(ctx, service.ID, contenders[winner].ID)
	check(err)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, contenders[loser].ID)
	if !errors.Is(err, ErrPPTPCapacity) {
		t.Fatal("detached credential reservation silently reused")
	}
	restored, err := p.AttachVPNClientAndRebuild(ctx, service.ID, contenders[winner].ID)
	check(err)
	if peers(restored)[contenders[winner].ID] != all[contenders[winner].ID] {
		t.Fatal("reattachment changed reserved credential")
	}
	t.Log("252 unique bindings, concurrent 253rd rejection, atomic generation/membership rollback, stable credentials and reserved reattachment verified")
}
