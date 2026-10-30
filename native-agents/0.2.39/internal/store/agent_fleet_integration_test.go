//go:build integration

package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"vpn-platform/internal/model"
)

func fleetFixture(t *testing.T) (context.Context, *Postgres, []string) {
	t.Helper()
	ctx, p := deletionStore(t)
	tenant, err := p.CreateTenant(ctx, "Agent fleet isolated test")
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, name := range []string{"first", "second", "offline"} {
		n, err := p.CreateNode(ctx, tenant.ID, name, "fleet-bootstrap-"+t.Name()+"-"+name)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, n.ID)
		_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_token_hash=$2,agent_version='0.2.27',os_name='ubuntu',os_version='24.04',architecture='amd64',last_seen_at=now(),status='online' WHERE id=$1::uuid`, n.ID, "fleet-agent-"+t.Name()+"-"+name)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Pool.Exec(ctx, `INSERT INTO node_health(node_id,healthy,applied_generation,checked_at) VALUES($1::uuid,true,0,now())`, n.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE nodes SET last_seen_at=now()-interval '1 day' WHERE id=$1::uuid`, ids[2]); err != nil {
		t.Fatal(err)
	}
	return ctx, p, ids
}
func fleetUpdated(t *testing.T, ctx context.Context, p *Postgres, id, v string) {
	t.Helper()
	if _, err := p.Pool.Exec(ctx, `UPDATE nodes SET agent_version=$2,last_seen_at=now() WHERE id=$1::uuid`, id, v); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pool.Exec(ctx, `UPDATE node_health SET healthy=true,checked_at=now() WHERE node_id=$1::uuid`, id); err != nil {
		t.Fatal(err)
	}
}

func TestAgentFleetSequentialIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	key := "22112211-1111-4111-8111-111111111111"
	id, err := p.StartAgentFleet(ctx, ids[0], key)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := p.StartAgentFleet(ctx, ids[0], key)
	if err != nil || replay != id {
		t.Fatal("start retry was not idempotent", err)
	}
	if _, err = p.StartAgentFleet(ctx, ids[1], key); !errors.Is(err, ErrAgentFleetConflict) {
		t.Fatal("request key rebound to another node")
	}
	if a, err := p.ClaimAgentUpdate(ctx, ids[2]); err != nil || a != nil {
		t.Fatal("offline node claimed update", err)
	}
	var wg sync.WaitGroup
	out := make(chan *model.AgentUpdateAssignment, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); a, e := p.ClaimAgentUpdate(ctx, ids[i%2]); out <- a; errs <- e }(i)
	}
	wg.Wait()
	close(out)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var a *model.AgentUpdateAssignment
	for value := range out {
		if value == nil {
			continue
		}
		if a != nil && (a.JobID != value.JobID || a.ClaimID != value.ClaimID) {
			t.Fatal("concurrent installers permitted")
		}
		a = value
	}
	if a == nil || !a.CanExecute {
		t.Fatal("no executable claim")
	}
	other := ids[0]
	if other == a.NodeID {
		other = ids[1]
	}
	report := model.AgentUpdateReport{ClaimID: a.ClaimID, Status: "succeeded", Code: "ready", BinarySHA256: a.Release.BinarySHA256}
	if err = p.ReportAgentUpdate(ctx, other, a.JobID, report); !errors.Is(err, ErrNotFound) {
		t.Fatal("another node reported success")
	}
	if err = p.ReportAgentUpdate(ctx, a.NodeID, a.JobID, report); !errors.Is(err, ErrAgentFleetConflict) {
		t.Fatal("success without target version accepted")
	}
	fleetUpdated(t, ctx, p, a.NodeID, a.Release.Version)
	wrong := report
	wrong.BinarySHA256 = strings.Repeat("a", 64)
	if err = p.ReportAgentUpdate(ctx, a.NodeID, a.JobID, wrong); !errors.Is(err, ErrAgentFleetConflict) {
		t.Fatal("wrong digest accepted")
	}
	if err = p.ReportAgentUpdate(ctx, a.NodeID, a.JobID, report); err != nil {
		t.Fatal(err)
	}
	if err = p.ReportAgentUpdate(ctx, a.NodeID, a.JobID, report); err != nil {
		t.Fatal("receipt replay rejected", err)
	}
	b, err := p.ClaimAgentUpdate(ctx, other)
	if err != nil || b == nil || b.NodeID != other {
		t.Fatal("next node did not continue", err)
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE agent_fleet_jobs SET claimed_at=now()-interval '11 minutes' WHERE id=$1::uuid`, b.JobID); err != nil {
		t.Fatal(err)
	}
	if err = p.ReconcileAgentFleet(ctx); err != nil {
		t.Fatal(err)
	}
	expired, err := p.ClaimAgentUpdate(ctx, other)
	if err != nil || expired == nil || expired.CanExecute || expired.ClaimID != b.ClaimID {
		t.Fatal("uncertain claim was lost or executable", err)
	}
	if err = p.SetAgentFleetPaused(ctx, id, false); !errors.Is(err, ErrAgentFleetConflict) {
		t.Fatal("uncertain installer resumed")
	}
	var count int
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_fleet_jobs WHERE status='claimed'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("uncertain global slot released")
	}
}

func TestAgentFleetFailureRetryIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	id, err := p.StartAgentFleet(ctx, ids[0], "22112211-1111-4111-8111-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.ClaimAgentUpdate(ctx, ids[0])
	if err != nil || a == nil {
		t.Fatal(err)
	}
	fail := model.AgentUpdateReport{ClaimID: a.ClaimID, Status: "failed", Code: "installer_failed"}
	if err = p.ReportAgentUpdate(ctx, a.NodeID, a.JobID, fail); err != nil {
		t.Fatal(err)
	}
	if err = p.ReportAgentUpdate(ctx, a.NodeID, a.JobID, fail); err != nil {
		t.Fatal(err)
	}
	if b, err := p.ClaimAgentUpdate(ctx, ids[1]); err != nil || b != nil {
		t.Fatal("failed canary did not pause fleet")
	}
	if err = p.SetAgentFleetPaused(ctx, id, false); !errors.Is(err, ErrAgentFleetConflict) {
		t.Fatal("failed job bypassed")
	}
	if err = p.RetryAgentUpdate(ctx, a.JobID); err != nil {
		t.Fatal(err)
	}
	b, err := p.ClaimAgentUpdate(ctx, a.NodeID)
	if err != nil || b == nil || b.ClaimID == a.ClaimID {
		t.Fatal("retry reused old execution identity")
	}
	if err = p.ReportAgentUpdate(ctx, a.NodeID, a.JobID, fail); !errors.Is(err, ErrAgentFleetConflict) {
		t.Fatal("old receipt finished new attempt")
	}
	var count int
	if err = p.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_fleet_attempts WHERE job_id=$1::uuid`, a.JobID).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed attempt evidence missing")
	}
}

func TestAgentFleetAutomaticAndPermissionsIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	denied := []context.Context{WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}}), WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "monitor"}}), WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: "22112211-1111-4111-8111-222222222222", Role: "operator"})}
	for _, scope := range denied {
		if _, err := p.StartAgentFleet(scope, ids[0], "22112211-1111-4111-8111-333333333333"); !errors.Is(err, ErrAdminPermission) {
			t.Fatal("unauthorized fleet write")
		}
		if err := p.RegisterAgentRelease(scope, model.AgentRelease{}); !errors.Is(err, ErrAdminPermission) {
			t.Fatal("unauthorized release registration")
		}
	}
	fleetUpdated(t, ctx, p, ids[0], "0.2.31")
	if err := p.ReconcileAgentFleet(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := p.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_fleet_runs`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unknown release triggered propagation")
	}
	fleetUpdated(t, ctx, p, ids[0], "0.2.30")
	if err := p.ReconcileAgentFleet(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Pool.QueryRow(ctx, `SELECT count(*) FROM agent_fleet_jobs`).Scan(&count); err != nil || count != 2 {
		t.Fatal("healthy reviewed upgrade did not propagate to remaining nodes")
	}
	a, err := p.ClaimAgentUpdate(ctx, ids[1])
	if err != nil || a == nil {
		t.Fatal(err)
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE agent_releases SET revoked=true WHERE version='0.2.30'`); err != nil {
		t.Fatal(err)
	}
	b, err := p.ClaimAgentUpdate(ctx, ids[1])
	if err != nil || b == nil || b.CanExecute {
		t.Fatal("revoked release executable")
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE agent_releases SET binary_sha256=$1 WHERE version='0.2.30'`, strings.Repeat("a", 64)); err == nil {
		t.Fatal("immutable released pin changed")
	}
	status, err := p.AgentFleetStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(status), a.ClaimID) || strings.Contains(string(status), "fleet-agent-") {
		t.Fatal("private node credential or claim leaked in UI status")
	}
}
