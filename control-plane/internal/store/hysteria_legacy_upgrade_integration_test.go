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

func TestHysteriaLegacyDesiredStateAndAgentUpgradeBoundaryIntegration(t *testing.T) {
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
			t.Fatal("legacy upgrade fixture operation failed", err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "SYNTHETIC-HYSTERIA-LEGACY-UPGRADE")
	check(err)
	legacy, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "hysteria2", Version: model.HysteriaLegacyVersion, OS: "linux", Architecture: "amd64", DownloadURL: model.HysteriaLegacyDownloadURL, SHA256: model.HysteriaLegacySHA256, Channel: "testing"})
	check(err)
	current, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "hysteria2", Version: model.HysteriaPinnedVersion, OS: "linux", Architecture: "amd64", DownloadURL: model.HysteriaPinnedDownloadURL, SHA256: model.HysteriaPinnedSHA256, Channel: "testing"})
	check(err)
	defer func() {
		_, _ = p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
		_, _ = p.Pool.Exec(context.Background(), `DELETE FROM core_releases WHERE id=$1::uuid OR id=$2::uuid`, legacy.ID, current.ID)
	}()
	check(p.ApproveCoreRelease(ctx, legacy.ID))
	check(p.ApproveCoreRelease(ctx, current.ID))
	bootstrap := security.HashToken("synthetic-legacy-hysteria-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "SYNTHETIC-HYSTERIA-LEGACY", bootstrap, "hysteria2")
	check(err)
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-legacy-hysteria-agent"), "0.2.25", "ubuntu", "24.04", "amd64", "hysteria2")
	check(err)
	state := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: "hysteria2", Version: legacy.Version, SHA256: legacy.SHA256, DownloadURL: legacy.DownloadURL, Channel: legacy.Channel}, Services: []model.ServiceSpec{}}
	check(p.SaveDesiredState(ctx, node.ID, state, legacy.ID))
	retried, changed, err := p.InitializeHysteriaRuntime(ctx, node.ID)
	check(err)
	if changed || retried.Generation != 1 || retried.Core.Version != model.HysteriaLegacyVersion {
		t.Fatal("new default silently migrated an existing legacy node")
	}
	state.Generation = 2
	check(p.SaveDesiredState(ctx, node.ID, state, legacy.ID))
	_, _, err = p.SetCoreUpdatePolicy(ctx, node.ID, "hysteria2", "pinned", legacy.Version)
	check(err)
	evaluation, err := p.EvaluateCoreUpdate(ctx, node.ID, "hysteria2", current.Version)
	check(err)
	if evaluation.Eligible || !strings.Contains(strings.Join(evaluation.Blockers, ","), "agent_upgrade_required") {
		t.Fatal("new core was offered to an agent that cannot verify it")
	}
	if _, _, err := p.SetCoreUpdatePolicy(ctx, node.ID, "hysteria2", "pinned", current.Version); !errors.Is(err, ErrNodeRuntime) {
		t.Fatal("new core pin bypassed the version-specific agent floor")
	}
	next := state
	next.Generation = 3
	next.Core = model.CoreRelease{Type: "hysteria2", Version: current.Version, SHA256: current.SHA256, DownloadURL: current.DownloadURL, Channel: current.Channel}
	if err := p.SaveDesiredState(ctx, node.ID, next, current.ID); !errors.Is(err, ErrNodeRuntime) {
		t.Fatal("new desired state bypassed the version-specific agent floor")
	}
	var generation int64
	check(p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, node.ID).Scan(&generation))
	if generation != 2 {
		t.Fatal("blocked upgrade changed the existing desired state")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.43' WHERE id=$1::uuid`, node.ID)
	check(err)
	_, _, err = p.SetCoreUpdatePolicy(ctx, node.ID, "hysteria2", "pinned", current.Version)
	check(err)
	check(p.SaveDesiredState(ctx, node.ID, next, current.ID))
	check(p.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, node.ID).Scan(&generation))
	if generation != 3 {
		t.Fatal("supported agent did not unlock the explicit reviewed upgrade")
	}
}
