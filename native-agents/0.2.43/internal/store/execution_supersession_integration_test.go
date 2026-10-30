//go:build integration

package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestExecutionFenceSupersededAssignment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(30*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
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
		t.Fatal("isolated DB required")
	}
	var tenant, node, owner string
	check(p.Pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('supersession test') RETURNING id::text`).Scan(&tenant))
	defer func() {
		_, e := p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant)
		check(e)
	}()
	check(p.Pool.QueryRow(ctx, `INSERT INTO nodes(tenant_id,name,status,desired_generation,applied_generation) VALUES($1::uuid,'supersession','online',1,0) RETURNING id::text`, tenant).Scan(&node))
	e := model.ExecutionAssignment{Generation: 1}
	check(p.Pool.QueryRow(ctx, `INSERT INTO deployments(node_id,generation,status,requested_core_version,core_type) VALUES($1::uuid,1,'applying','26.7.28','xray') RETURNING id::text,execution_id::text,execution_epoch`, node).Scan(&e.DeploymentID, &e.ExecutionID, &e.ExecutionEpoch))
	check(p.Pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&owner))
	proof := security.HashToken("isolated supersession proof")
	_, err = p.Pool.Exec(ctx, `INSERT INTO deployment_execution_leases(deployment_id,node_id,generation,execution_id,execution_epoch,state,owner_instance_id,lease_token_hash,claimed_at,renewed_at,lease_expires_at) VALUES($1::uuid,$2::uuid,1,$3::uuid,$4,'active',$5::uuid,$6,now()-interval '2 minutes',now()-interval '1 minute',now()-interval '30 seconds')`, e.DeploymentID, node, e.ExecutionID, e.ExecutionEpoch, owner, proof)
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO desired_states(node_id,generation,document) VALUES($1::uuid,1,'{"generation":1}'),($1::uuid,2,'{"generation":2}')`, node)
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO deployments(node_id,generation,status,requested_core_version,core_type) VALUES($1::uuid,2,'pending','26.7.28','xray')`, node)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET desired_generation=2 WHERE id=$1::uuid`, node)
	check(err)
	newer := model.ExecutionAssignment{Generation: 2}
	check(p.Pool.QueryRow(ctx, `SELECT id::text,execution_id::text,execution_epoch FROM deployments WHERE node_id=$1::uuid AND generation=2`, node).Scan(&newer.DeploymentID, &newer.ExecutionID, &newer.ExecutionEpoch))
	if _, err = p.ClaimExecutionLease(ctx, node, newer, owner, proof, time.Minute); err == nil {
		t.Fatal("new worker accepted before old physical owner stopped")
	}
	type concurrentResult struct {
		assignment model.AgentAssignment
		exists     bool
		err        error
	}
	results := make(chan concurrentResult, 20)
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			<-start
			a, exists, e := p.AgentAssignment(ctx, node)
			results <- concurrentResult{a, exists, e}
		}()
	}
	close(start)
	var fenceID string
	for i := 0; i < 20; i++ {
		r := <-results
		check(r.err)
		if !r.exists || r.assignment.Execution.Generation != 1 || r.assignment.FenceRequest == nil {
			t.Fatal("concurrent request skipped physical fence")
		}
		id := r.assignment.FenceRequest.ID
		if fenceID == "" {
			fenceID = id
		}
		if id != fenceID {
			t.Fatal("concurrent requests created different fences")
		}
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM execution_fence_requests WHERE deployment_id=$1::uuid`, e.DeploymentID).Scan(&count))
	if count != 1 {
		t.Fatal("duplicate physical fences")
	}
	a, exists, err := p.AgentAssignment(ctx, node)
	check(err)
	if !exists || a.Execution.Generation != 1 || a.FenceRequest == nil {
		t.Fatal("superseded owner was hidden by newer generation")
	}
	again, _, err := p.AgentAssignment(ctx, node)
	check(err)
	if again.FenceRequest == nil || again.FenceRequest.ID != a.FenceRequest.ID {
		t.Fatal("fence is not idempotent")
	}
	if _, err = p.AcknowledgeExecutionFenceRequest(ctx, node, a.FenceRequest.ID, e, owner, security.HashToken("wrong")); err == nil {
		t.Fatal("invalid physical proof accepted")
	}
	_, err = p.AcknowledgeExecutionFenceRequest(ctx, node, a.FenceRequest.ID, e, owner, proof)
	check(err)
	latest, exists, err := p.AgentAssignment(ctx, node)
	check(err)
	if !exists || latest.Execution.Generation != 2 || latest.FenceRequest != nil {
		t.Fatal("new generation not released after physical fence")
	}
	_, err = p.ClaimExecutionLease(ctx, node, newer, owner, proof, time.Minute)
	check(err)
	var state string
	check(p.Pool.QueryRow(ctx, `SELECT state FROM deployment_execution_leases WHERE deployment_id=$1::uuid`, e.DeploymentID).Scan(&state))
	if state != "fenced" {
		t.Fatal("old lease still active")
	}
}
