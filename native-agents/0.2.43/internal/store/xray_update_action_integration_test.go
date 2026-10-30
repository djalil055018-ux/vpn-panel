//go:build integration

package store

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"vpn-platform/internal/model"
)

func TestReviewedXrayUpdateIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	node := ids[0]
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	old, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.7.28", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/old.zip", SHA256: strings.Repeat("a", 64), Channel: "testing"})
	check(err)
	check(p.ApproveCoreRelease(ctx, old.ID))
	next, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.9.9", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/new.zip", SHA256: strings.Repeat("b", 64), Channel: "testing", UpstreamPrerelease: true})
	check(err)
	check(p.ApproveCoreRelease(ctx, next.ID))
	state := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: old.Type, Version: old.Version, DownloadURL: old.DownloadURL, SHA256: old.SHA256, Channel: old.Channel}}
	check(p.SaveDesiredState(ctx, node, state, old.ID))
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET applied_generation=desired_generation WHERE id=$1::uuid`, node)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE node_health SET core='xray',core_version='26.7.28',applied_generation=1,checked_at=now() WHERE node_id=$1::uuid`, node)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE deployments SET status='healthy',completed_at=now(),applied_core_version='26.7.28' WHERE node_id=$1::uuid`, node)
	check(err)
	key := "22112211-1111-4111-8111-444444444444"
	if _, err = p.StartReviewedXrayUpdate(ctx, node, next.ID, key, false); !errors.Is(err, ErrReviewedXrayUpdate) {
		t.Fatal("prerelease accepted without consent", err)
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM rollout_plans WHERE node_id=$1::uuid`, node).Scan(&count))
	if count != 0 {
		t.Fatal("rejected prerelease mutated plans")
	}
	denied := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "monitor"}})
	if _, err = p.StartReviewedXrayUpdate(denied, node, next.ID, key, true); !errors.Is(err, ErrAdminPermission) {
		t.Fatal("monitor started Xray update")
	}
	admin := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}})
	var wg sync.WaitGroup
	plans := make(chan model.RolloutPlan, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			plan, e := p.StartReviewedXrayUpdate(admin, node, next.ID, key, true)
			plans <- plan
			errs <- e
		}()
	}
	wg.Wait()
	close(plans)
	close(errs)
	for e := range errs {
		check(e)
	}
	first := ""
	for plan := range plans {
		if plan.Status != "executed" || plan.TargetCoreReleaseID != next.ID || plan.ProposedGeneration != 2 {
			t.Fatal("unexpected update receipt", plan.Status)
		}
		if first != "" && plan.ID != first {
			t.Fatal("duplicate plans on POST retries")
		}
		first = plan.ID
	}
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM desired_states WHERE node_id=$1::uuid`, node).Scan(&count))
	if count != 2 {
		t.Fatal("more than one new generation")
	}
	if _, err = p.StartReviewedXrayUpdate(ctx, ids[1], next.ID, key, true); !errors.Is(err, ErrReviewedXrayUpdate) {
		t.Fatal("request key rebound across nodes")
	}
	if _, err = p.StartReviewedXrayUpdate(ctx, node, old.ID, key, true); !errors.Is(err, ErrReviewedXrayUpdate) {
		t.Fatal("request key rebound across releases")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET applied_generation=desired_generation WHERE id=$1::uuid`, node)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE node_health SET core_version='26.9.9',applied_generation=2,checked_at=now() WHERE node_id=$1::uuid`, node)
	check(err)
	if _, err = p.StartReviewedXrayUpdate(ctx, node, old.ID, "22112211-1111-4111-8111-555555555555", true); !errors.Is(err, ErrReviewedXrayUpdate) {
		t.Fatal("automatic downgrade accepted")
	}
}
