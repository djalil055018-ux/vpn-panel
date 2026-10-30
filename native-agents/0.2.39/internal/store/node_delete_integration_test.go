//go:build integration

package store

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestNodeDeleteIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	id := ids[2]
	for _, role := range []string{"admin", "monitor"} {
		_, e := p.DeleteNode(WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: role}}), id, "offline", true)
		if !errors.Is(e, ErrAdminPermission) {
			t.Fatal("role bypass", e)
		}
	}
	_, e := p.DeleteNode(WithTenantPrincipal(ctx, model.TenantAPIToken{Role: "operator"}), id, "offline", true)
	if !errors.Is(e, ErrAdminPermission) {
		t.Fatal("tenant bypass", e)
	}
	for _, c := range []struct {
		name    string
		stopped bool
	}{{"wrong", true}, {"offline", false}} {
		_, e = p.DeleteNode(ctx, id, c.name, c.stopped)
		if !errors.Is(e, ErrNodeDeleteConfirmation) {
			t.Fatal("confirmation bypass", e)
		}
	}
	_, e = p.DeleteNode(ctx, ids[0], "first", true)
	if !errors.Is(e, ErrNodeDeleteBusy) {
		t.Fatal("live node deleted", e)
	}
	run, e := p.StartAgentFleet(ctx, ids[0], "33221100-1111-4111-8111-111111111111")
	check(e)
	check(p.SetAgentFleetPaused(ctx, run, true))
	_, e = p.DeleteNode(ctx, id, "offline", true)
	if !errors.Is(e, ErrNodeDeleteBusy) {
		t.Fatal("paused run fence erased", e)
	}
	check(p.SetAgentFleetPaused(ctx, run, false))
	var wg sync.WaitGroup
	out := make(chan NodeDeletion, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); v, e := p.DeleteNode(ctx, id, "offline", true); out <- v; errs <- e }()
	}
	wg.Wait()
	close(out)
	close(errs)
	for e := range errs {
		check(e)
	}
	var deletedAt time.Time
	for v := range out {
		if !v.Deleted || v.NodeID != id {
			t.Fatal("receipt missing")
		}
		if !deletedAt.IsZero() && !v.DeletedAt.Equal(deletedAt) {
			t.Fatal("retry changed receipt")
		}
		deletedAt = v.DeletedAt
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE node_id=$1::uuid AND event_type='node.deleted'`, id).Scan(&count))
	if count != 1 {
		t.Fatal("duplicate audit", count)
	}
	var status, message string
	check(p.Pool.QueryRow(ctx, `SELECT status,message FROM agent_fleet_jobs WHERE run_id=$1::uuid AND node_id=$2::uuid`, run, id).Scan(&status, &message))
	if status != "superseded" || message != "node_retired" {
		t.Fatal("queued job still live")
	}
	if _, e = p.NodeByAgentToken(ctx, "fleet-agent-"+t.Name()+"-offline"); !errors.Is(e, ErrNotFound) {
		t.Fatal("credential still accepted", e)
	}
	if _, e = p.RotateNodeBootstrapToken(ctx, id, "new-bootstrap"); !errors.Is(e, ErrNodeRetired) {
		t.Fatal("identity revived", e)
	}
	if _, e = p.ClaimAgentUpdate(ctx, id); !errors.Is(e, ErrNodeRetired) {
		t.Fatal("late updater accepted", e)
	}
	for _, query := range []string{`UPDATE nodes SET status='online' WHERE id=$1::uuid`, `UPDATE nodes SET agent_token_hash='revived' WHERE id=$1::uuid`, `UPDATE node_health SET checked_at=now() WHERE node_id=$1::uuid`, `DELETE FROM node_retirements WHERE node_id=$1::uuid`, `DELETE FROM nodes WHERE id=$1::uuid`} {
		if _, e = p.Pool.Exec(ctx, query, id); e == nil {
			t.Fatal("retirement fence bypassed", query)
		}
	}
	nodes, e := p.ListNodes(ctx)
	check(e)
	for _, n := range nodes {
		if n.ID == id {
			t.Fatal("deleted node listed as active")
		}
	}
	removed, e := p.ListNodesByDeletion(ctx, true)
	check(e)
	if len(removed) != 1 || removed[0].ID != id {
		t.Fatal("history list missing")
	}
	life, e := p.NodeLifecycle(ctx, id, time.Now())
	check(e)
	if life.State != "retired" || life.Registered || life.Online || life.Healthy || life.RollbackReady {
		t.Fatal("false lifecycle", life)
	}
	diag, e := p.NodeDiagnostics(ctx, id, time.Now())
	check(e)
	if diag.Overall != "ok" || diag.LifecycleState != "retired" {
		t.Fatal("retired node marked failed")
	}
	runtime, e := p.NodeRuntimeStatus(ctx, id)
	check(e)
	if runtime.Healthy || runtime.RollbackReady || runtime.NodeStatus != "retired" {
		t.Fatal("retired runtime marked healthy")
	}
	raw, e := p.AgentFleetStatus(ctx)
	check(e)
	var fleet struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
	}
	check(json.Unmarshal(raw, &fleet))
	for _, n := range fleet.Nodes {
		if n.ID == id {
			t.Fatal("deleted node in fleet")
		}
	}
	check(p.ReconcileAgentFleet(ctx))
	operations, e := p.OperationsStatus(ctx)
	check(e)
	for _, n := range operations.Nodes {
		if n.ID == id {
			t.Fatal("deleted node monitored")
		}
	}
	var tenant string
	check(p.Pool.QueryRow(ctx, `SELECT tenant_id::text FROM nodes WHERE id=$1::uuid`, id).Scan(&tenant))
	replacement, e := p.CreateNode(ctx, tenant, "offline", "replacement-bootstrap")
	check(e)
	if replacement.ID == id {
		t.Fatal("old identity reused")
	}
	if _, e = p.CreateNode(ctx, tenant, "offline", "duplicate-bootstrap"); e == nil {
		t.Fatal("duplicate active name accepted")
	}
	if _, e = p.DeleteNode(ctx, id, "offline", true); e != nil {
		t.Fatal("old deletion retry affected replacement", e)
	}
}

func TestNodeDeleteClaimFenceIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	_, e := p.StartAgentFleet(ctx, ids[0], "33221100-1111-4111-8111-222222222222")
	if e != nil {
		t.Fatal(e)
	}
	claim, e := p.ClaimAgentUpdate(ctx, ids[0])
	if e != nil || claim == nil {
		t.Fatal("claim setup", e)
	}
	if _, e = p.Pool.Exec(ctx, `UPDATE nodes SET last_seen_at=now()-interval '1 day' WHERE id=$1::uuid`, ids[0]); e != nil {
		t.Fatal(e)
	}
	if _, e = p.DeleteNode(ctx, ids[0], "first", true); !errors.Is(e, ErrNodeDeleteBusy) {
		t.Fatal("claimed installer fence lost", e)
	}
	var status string
	if e = p.Pool.QueryRow(ctx, `SELECT status FROM agent_fleet_jobs WHERE id=$1::uuid`, claim.JobID).Scan(&status); e != nil || status != "claimed" {
		t.Fatal("claim changed", e)
	}
}

func TestNodeDeleteOnlineDecommissionIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	_, services := nativeAccessFixture(t, ctx, p)
	var nodeID string
	if err := p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, services[0]).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	owner := WithAdminPrincipal(ctx, model.AdminSession{Account: model.AdminAccount{Role: "owner"}})
	first, err := p.DeleteNodeWithOptions(owner, nodeID, "first", false, true)
	check(err)
	if first.Deleted || !first.Decommissioning || first.Generation <= 0 {
		t.Fatal("online node was not safely decommissioned", first)
	}
	var status string
	check(p.Pool.QueryRow(ctx, `SELECT status FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&status))
	if status != "decommissioning" {
		t.Fatal("node did not enter decommissioning state", status)
	}
	if _, err = p.DeleteNodeWithOptions(owner, nodeID, "first", false, true); !errors.Is(err, ErrNodeDeleteBusy) {
		t.Fatal("node was retired before applying the empty generation", err)
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET applied_generation=$2 WHERE id=$1::uuid`, nodeID, first.Generation)
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO node_health(node_id,healthy,applied_generation,checked_at) VALUES($1::uuid,true,$2,now()) ON CONFLICT(node_id) DO UPDATE SET healthy=true,applied_generation=EXCLUDED.applied_generation,checked_at=now()`, nodeID, first.Generation)
	check(err)
	final, err := p.DeleteNodeWithOptions(owner, nodeID, "first", false, true)
	check(err)
	if !final.Deleted || final.Decommissioning {
		t.Fatal("online node did not retire after convergence", final)
	}
	var stopped bool
	var generation int64
	check(p.Pool.QueryRow(ctx, `SELECT server_stopped,decommission_generation FROM node_retirements WHERE node_id=$1::uuid`, nodeID).Scan(&stopped, &generation))
	if stopped || generation != first.Generation {
		t.Fatal("retirement receipt lost its safe decommission evidence", stopped, generation)
	}
}

func TestNodeDeleteStoppedNodeClosesStaleApplyingDeploymentsIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var tenant, deploymentID, planID string
	check(p.Pool.QueryRow(ctx, `SELECT tenant_id::text FROM nodes WHERE id=$1::uuid`, ids[2]).Scan(&tenant))
	check(p.Pool.QueryRow(ctx, `INSERT INTO deployments(node_id,generation,status,started_at,updated_at)
VALUES($1::uuid,999,'applying',now()-interval '8 days',now()-interval '8 days') RETURNING id::text`, ids[2]).Scan(&deploymentID))
	check(p.Pool.QueryRow(ctx, `INSERT INTO rollout_plans(tenant_id,node_id,core_type,policy,base_generation,proposed_generation,status,deployment_id,outcome_status)
VALUES($1::uuid,$2::uuid,'xray','stable',998,999,'executed',$3::uuid,'applying') RETURNING id::text`, tenant, ids[2], deploymentID).Scan(&planID))

	deleted, err := p.DeleteNode(ctx, ids[2], "offline", true)
	check(err)
	if !deleted.Deleted {
		t.Fatal("offline node with stale deployment was not retired")
	}
	var deploymentStatus, failure string
	check(p.Pool.QueryRow(ctx, `SELECT status,error_message FROM deployments WHERE id=$1::uuid`, deploymentID).Scan(&deploymentStatus, &failure))
	if deploymentStatus != "failed" || failure != "node_retired_before_deployment_converged" {
		t.Fatal("stale deployment history was not closed safely", deploymentStatus, failure)
	}
	var outcome, outcomeReason string
	check(p.Pool.QueryRow(ctx, `SELECT outcome_status,outcome_reason FROM rollout_plans WHERE id=$1::uuid`, planID).Scan(&outcome, &outcomeReason))
	if outcome != "failed" || outcomeReason != failure {
		t.Fatal("rollout outcome was not closed with its deployment", outcome, outcomeReason)
	}
	var auditCount int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE node_id=$1::uuid AND event_type IN ('deployment.failed','rollout_plan.outcome_changed','node.deleted')`, ids[2]).Scan(&auditCount))
	if auditCount != 3 {
		t.Fatal("retirement or deployment audit evidence is incomplete", auditCount)
	}
}

func TestNodeDeleteStoppedNodeStillBlocksActiveDeploymentLeaseIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	var deploymentID, executionID string
	if err := p.Pool.QueryRow(ctx, `INSERT INTO deployments(node_id,generation,status)
VALUES($1::uuid,1000,'applying') RETURNING id::text,execution_id::text`, ids[2]).Scan(&deploymentID, &executionID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Pool.Exec(ctx, `INSERT INTO deployment_execution_leases(deployment_id,node_id,generation,execution_id,execution_epoch,state,owner_instance_id,lease_token_hash,claimed_at,renewed_at,lease_expires_at)
SELECT id,node_id,generation,execution_id,execution_epoch,'active','11111111-1111-4111-8111-111111111111'::uuid,'synthetic-active-proof',now(),now(),now()+interval '1 minute' FROM deployments WHERE id=$1::uuid`, deploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DeleteNode(ctx, ids[2], "offline", true); !errors.Is(err, ErrNodeDeleteBusy) {
		t.Fatal("active execution lease was ignored", err)
	}
	var status string
	if err := p.Pool.QueryRow(ctx, `SELECT status FROM deployments WHERE id=$1::uuid`, deploymentID).Scan(&status); err != nil || status != "applying" {
		t.Fatal("active deployment was altered", status, err)
	}
}

func TestNodeDeleteClientHistoryIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, services := nativeAccessFixture(t, ctx, p)
	c, e := p.CreateVPNClient(ctx, tenant, "Surviving account", nil)
	check(e)
	for _, s := range services {
		_, e = p.AttachVPNClientAndRebuild(ctx, s, c.ID)
		check(e)
	}
	var id string
	check(p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, services[0]).Scan(&id))
	_, e = p.Pool.Exec(ctx, `UPDATE nodes SET last_seen_at=now()-interval '1 day' WHERE id=$1::uuid`, id)
	check(e)
	var before string
	check(p.Pool.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY generation),'[]')::text FROM desired_states d WHERE node_id=$1::uuid`, id).Scan(&before))
	_, e = p.DeleteNode(ctx, id, "first", true)
	check(e)
	if e = p.SaveTrafficDelivery(ctx, id, model.TrafficDelivery{RecordedAt: time.Now(), Snapshot: model.ClientTrafficSnapshot{Sequence: 1, Epoch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Clients: []model.ClientTraffic{{ClientID: c.ID, Uplink: 500}}}}); !errors.Is(e, ErrNodeRetired) {
		t.Fatal("late retired traffic accepted", e)
	}
	survivor, e := p.GetVPNClient(ctx, c.ID)
	check(e)
	if survivor.VLESSUUID != c.VLESSUUID || survivor.Status != c.Status {
		t.Fatal("client changed")
	}
	if _, e = p.BootstrapAgentForRuntime(ctx, security.HashToken("native-test-bootstrap-"+tenant+"first"), "new-agent", "0.2.31", "ubuntu", "24.04", "amd64", "xray"); e == nil {
		t.Fatal("old bootstrap accepted")
	}
	if _, e = p.SetVPNServiceEnabledAndRebuild(ctx, services[0], true); e == nil {
		t.Fatal("retired service revived")
	}
	_, e = p.SetVPNClientStatus(ctx, c.ID, "disabled")
	check(e)
	_, e = p.DeleteVPNClient(ctx, c.ID, c.Name)
	check(e)
	var after string
	check(p.Pool.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY generation),'[]')::text FROM desired_states d WHERE node_id=$1::uuid`, id).Scan(&after))
	if before != after {
		t.Fatal("retained history rewritten")
	}
	stuck, e := p.DetectStuckDeployments(ctx, 100, time.Now().Add(2*time.Hour))
	check(e)
	for _, d := range stuck {
		if d.NodeID == id {
			t.Fatal("retired deployment reconciled")
		}
	}
}

func TestNodeDeleteCertificateAndAtomicIntegration(t *testing.T) {
	ctx, p, ids := fleetFixture(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	id := ids[2]
	cert, e := p.CreateNodeCertificate(ctx, id, "retired.example.test", "letsencrypt", "http-01", "staging", nil, true)
	check(e)
	_, e = p.QueueCertificateJob(ctx, cert.ID, "issue")
	check(e)
	work, e := p.ClaimCertificateJob(ctx, id, "11111111-1111-4111-8111-111111111111", "synthetic-cert-lease", time.Minute)
	check(e)
	if _, e = p.DeleteNode(ctx, id, "offline", true); !errors.Is(e, ErrNodeDeleteBusy) {
		t.Fatal("certificate claim lost", e)
	}
	check(p.CompleteCertificateJob(ctx, id, model.CertificateJobResult{JobID: work.JobID, CertificateID: cert.ID, Success: false, ErrorMessage: "synthetic issuance failure"}, "synthetic-cert-lease"))
	_, e = p.QueueCertificateJob(ctx, cert.ID, "issue")
	check(e)
	_, e = p.Pool.Exec(ctx, `CREATE FUNCTION reject_node_retirement_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic receipt failure'; END $$;CREATE TRIGGER reject_node_retirement_fixture BEFORE INSERT ON node_retirements FOR EACH ROW EXECUTE FUNCTION reject_node_retirement_fixture()`)
	check(e)
	if _, e = p.DeleteNode(ctx, id, "offline", true); e == nil {
		t.Fatal("partial deletion accepted")
	}
	var intact bool
	check(p.Pool.QueryRow(ctx, `SELECT n.agent_token_hash IS NOT NULL AND n.status<>'retired' AND c.auto_renew AND EXISTS(SELECT 1 FROM certificate_jobs WHERE node_id=n.id AND status='pending') FROM nodes n JOIN node_certificates c ON c.node_id=n.id WHERE n.id=$1::uuid`, id).Scan(&intact))
	if !intact {
		t.Fatal("failed deletion committed side effects")
	}
	_, e = p.Pool.Exec(ctx, `DROP TRIGGER reject_node_retirement_fixture ON node_retirements;DROP FUNCTION reject_node_retirement_fixture()`)
	check(e)
	_, e = p.DeleteNode(ctx, id, "offline", true)
	check(e)
	check(p.Pool.QueryRow(ctx, `SELECT NOT c.auto_renew AND NOT EXISTS(SELECT 1 FROM certificate_jobs WHERE node_id=c.node_id AND status IN ('pending','claimed')) FROM node_certificates c WHERE c.id=$1::uuid`, cert.ID).Scan(&intact))
	if !intact {
		t.Fatal("certificate work remained live")
	}
	if _, e = p.QueueCertificateJob(ctx, cert.ID, "issue"); e == nil {
		t.Fatal("retired certificate restarted")
	}
	if _, e = p.Pool.Exec(ctx, `UPDATE node_certificates SET auto_renew=true WHERE id=$1::uuid`, cert.ID); e == nil {
		t.Fatal("retired auto renewal enabled")
	}
}
