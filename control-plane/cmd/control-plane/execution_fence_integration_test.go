//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestExecutionFenceHTTPFlowE2E(
	t *testing.T,
) {
	dsn :=
		os.Getenv(
			"DATABASE_URL",
		)

	if dsn == "" {
		t.Fatal(
			"DATABASE_URL is required",
		)
	}

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			30*time.Second,
		)

	defer cancel()

	db, err :=
		store.NewPostgres(
			ctx,
			dsn,
		)

	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	app :=
		&application{
			store: db,

			adminToken: "integration-admin-token",
		}

	var tenantID string
	var nodeID string
	var deploymentID string
	var executionID string
	var executionEpoch int64

	tenantName :=
		fmt.Sprintf(
			"D4C2A-HTTP-%d",
			time.Now().UnixNano(),
		)

	err =
		db.Pool.QueryRow(
			ctx,
			`
			INSERT INTO tenants(name)
			VALUES($1::text)
			RETURNING id::text
			`,
			tenantName,
		).Scan(
			&tenantID,
		)

	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		cleanupCtx, cleanupCancel :=
			context.WithTimeout(
				context.Background(),
				10*time.Second,
			)

		defer cleanupCancel()

		if _, err :=
			db.Pool.Exec(
				cleanupCtx,
				`
				DELETE FROM tenants
				WHERE id=$1::uuid
				`,
				tenantID,
			); err != nil {

			t.Errorf(
				"fixture cleanup failed: %v",
				err,
			)
		}
	}()

	err =
		db.Pool.QueryRow(
			ctx,
			`
			INSERT INTO nodes(
				tenant_id,
				name,
				status,
				desired_generation,
				applied_generation,
				execution_epoch
			)
			VALUES(
				$1::uuid,
				$2::text,
				'online',
				1,
				0,
				0
			)
			RETURNING id::text
			`,
			tenantID,
			"D4C2A-TEMP-NODE",
		).Scan(
			&nodeID,
		)

	if err != nil {
		t.Fatal(err)
	}

	desired :=
		model.DesiredState{
			Generation: 1,

			Core: model.CoreRelease{
				Type: "xray",

				Version: "26.7.28",
			},

			Services: []model.ServiceSpec{},
		}

	desiredRaw, err :=
		json.Marshal(
			desired,
		)

	if err != nil {
		t.Fatal(err)
	}

	_, err =
		db.Pool.Exec(
			ctx,
			`
			INSERT INTO desired_states(
				node_id,
				generation,
				document
			)
			VALUES(
				$1::uuid,
				1,
				$2::jsonb
			)
			`,
			nodeID,
			string(desiredRaw),
		)

	if err != nil {
		t.Fatal(err)
	}

	err =
		db.Pool.QueryRow(
			ctx,
			`
			INSERT INTO deployments(
				node_id,
				generation,
				status,
				requested_core_version,
				core_type
			)
			VALUES(
				$1::uuid,
				1,
				'applying',
				'26.7.28',
				'xray'
			)
			RETURNING
				id::text,
				execution_id::text,
				execution_epoch
			`,
			nodeID,
		).Scan(
			&deploymentID,
			&executionID,
			&executionEpoch,
		)

	if err != nil {
		t.Fatal(err)
	}

	execution :=
		model.ExecutionAssignment{
			DeploymentID: deploymentID,

			Generation: 1,

			ExecutionID: executionID,

			ExecutionEpoch: executionEpoch,
		}

	var ownerInstanceID string

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT gen_random_uuid()::text
			`,
		).Scan(
			&ownerInstanceID,
		)

	if err != nil {
		t.Fatal(err)
	}

	rawLeaseToken, err :=
		security.NewToken(48)

	if err != nil {
		t.Fatal(err)
	}

	leaseHash :=
		security.HashToken(
			rawLeaseToken,
		)

	_, err =
		db.Pool.Exec(
			ctx,
			`
			INSERT INTO deployment_execution_leases(
				deployment_id,
				node_id,
				generation,
				execution_id,
				execution_epoch,
				state,
				owner_instance_id,
				lease_token_hash,
				claimed_at,
				renewed_at,
				lease_expires_at
			)
			VALUES(
				$1::uuid,
				$2::uuid,
				1,
				$3::uuid,
				$4::bigint,
				'active',
				$5::uuid,
				$6::text,
				now() - interval '10 seconds',
				now() - interval '5 seconds',
				now() + interval '55 seconds'
			)
			`,
			deploymentID,
			nodeID,
			executionID,
			executionEpoch,
			ownerInstanceID,
			leaseHash,
		)

	if err != nil {
		t.Fatal(err)
	}

	// -------------------------------------------------
	// 1. ADMIN creates the physical fence request.
	// -------------------------------------------------

	adminBody :=
		[]byte(
			`{"reason":"integration physical fence"}`,
		)

	adminRequest :=
		httptest.NewRequest(
			http.MethodPost,
			"/api/v1/nodes/"+
				nodeID+
				"/deployments/1/fence",
			bytes.NewReader(
				adminBody,
			),
		)

	adminRequest.SetPathValue(
		"id",
		nodeID,
	)

	adminRequest.SetPathValue(
		"generation",
		"1",
	)

	adminRecorder :=
		httptest.NewRecorder()

	app.createExecutionFenceRequest(
		adminRecorder,
		adminRequest,
	)

	if adminRecorder.Code !=
		http.StatusOK {

		t.Fatalf(
			"admin fence status=%d body=%s",
			adminRecorder.Code,
			adminRecorder.Body.String(),
		)
	}

	var fenceRequest model.ExecutionFenceRequest

	if err :=
		json.NewDecoder(
			adminRecorder.Body,
		).Decode(
			&fenceRequest,
		); err != nil {

		t.Fatal(err)
	}

	if fenceRequest.ID == "" {
		t.Fatal(
			"fence request id is empty",
		)
	}

	if fenceRequest.State !=
		"requested" {

		t.Fatalf(
			"fence state=%q want=requested",
			fenceRequest.State,
		)
	}

	if fenceRequest.DeploymentID !=
		deploymentID ||
		fenceRequest.Generation !=
			1 ||
		fenceRequest.ExecutionID !=
			executionID ||
		fenceRequest.ExecutionEpoch !=
			executionEpoch {

		t.Fatal(
			"admin fence exact execution identity mismatch",
		)
	}

	if fenceRequest.TargetOwnerInstanceID !=
		ownerInstanceID {

		t.Fatalf(
			"target owner=%q want=%q",
			fenceRequest.TargetOwnerInstanceID,
			ownerInstanceID,
		)
	}

	// -------------------------------------------------
	// 2. Agent assignment must expose exact requested
	//    fence without a second source of truth.
	// -------------------------------------------------

	assignmentRequest :=
		httptest.NewRequest(
			http.MethodGet,
			"/api/v1/agent/assignment",
			nil,
		)

	assignmentRequest =
		assignmentRequest.WithContext(
			context.WithValue(
				assignmentRequest.Context(),
				nodeContextKey,
				model.Node{
					ID: nodeID,

					TenantID: tenantID,
				},
			),
		)

	assignmentRecorder :=
		httptest.NewRecorder()

	app.agentAssignment(
		assignmentRecorder,
		assignmentRequest,
	)

	if assignmentRecorder.Code !=
		http.StatusOK {

		t.Fatalf(
			"assignment status=%d body=%s",
			assignmentRecorder.Code,
			assignmentRecorder.Body.String(),
		)
	}

	var assignment model.AgentAssignment

	if err :=
		json.NewDecoder(
			assignmentRecorder.Body,
		).Decode(
			&assignment,
		); err != nil {

		t.Fatal(err)
	}

	if assignment.FenceRequest ==
		nil {

		t.Fatal(
			"assignment has no fence_request",
		)
	}

	if assignment.FenceRequest.ID !=
		fenceRequest.ID {

		t.Fatalf(
			"assignment fence id=%q want=%q",
			assignment.FenceRequest.ID,
			fenceRequest.ID,
		)
	}

	if assignment.FenceRequest.ExecutionID !=
		executionID ||
		assignment.FenceRequest.ExecutionEpoch !=
			executionEpoch ||
		assignment.FenceRequest.TargetOwnerInstanceID !=
			ownerInstanceID {

		t.Fatal(
			"assignment fence physical identity mismatch",
		)
	}

	// -------------------------------------------------
	// 3. Wrong proof must return generic 409 and must
	//    not expose the proof value or its reason.
	// -------------------------------------------------

	wrongProof :=
		"D4C2A-WRONG-PROOF-MUST-NOT-LEAK"

	wrongAck :=
		model.ExecutionFenceAckRequest{
			FenceRequestID: fenceRequest.ID,

			Execution: execution,

			OwnerInstanceID: ownerInstanceID,

			FenceProofToken: wrongProof,
		}

	wrongRaw, err :=
		json.Marshal(
			wrongAck,
		)

	if err != nil {
		t.Fatal(err)
	}

	wrongRequest :=
		httptest.NewRequest(
			http.MethodPost,
			"/api/v1/agent/execution/fence-ack",
			bytes.NewReader(
				wrongRaw,
			),
		)

	wrongRequest =
		wrongRequest.WithContext(
			context.WithValue(
				wrongRequest.Context(),
				nodeContextKey,
				model.Node{
					ID: nodeID,

					TenantID: tenantID,
				},
			),
		)

	wrongRecorder :=
		httptest.NewRecorder()

	app.agentExecutionFenceAck(
		wrongRecorder,
		wrongRequest,
	)

	if wrongRecorder.Code !=
		http.StatusConflict {

		t.Fatalf(
			"wrong proof status=%d body=%s",
			wrongRecorder.Code,
			wrongRecorder.Body.String(),
		)
	}

	if strings.Contains(
		wrongRecorder.Body.String(),
		wrongProof,
	) {
		t.Fatal(
			"wrong raw proof leaked in HTTP response",
		)
	}

	if strings.Contains(
		strings.ToLower(
			wrongRecorder.Body.String(),
		),
		"proof invalid",
	) {
		t.Fatal(
			"HTTP response disclosed proof failure detail",
		)
	}

	// Failed ACK must not mutate the physical fence state.
	var requestState string
	var leaseState string

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				f.state,
				l.state
			FROM execution_fence_requests f
			JOIN deployment_execution_leases l
				ON l.deployment_id=f.deployment_id
			WHERE f.id=$1::uuid
			`,
			fenceRequest.ID,
		).Scan(
			&requestState,
			&leaseState,
		)

	if err != nil {
		t.Fatal(err)
	}

	if requestState !=
		"requested" ||
		leaseState !=
			"active" {

		t.Fatalf(
			"wrong ACK mutated request=%q lease=%q",
			requestState,
			leaseState,
		)
	}

	// -------------------------------------------------
	// 4. Correct RAM-only lease proof ACKs the fence.
	// -------------------------------------------------

	validAck :=
		model.ExecutionFenceAckRequest{
			FenceRequestID: fenceRequest.ID,

			Execution: execution,

			OwnerInstanceID: ownerInstanceID,

			FenceProofToken: rawLeaseToken,
		}

	validRaw, err :=
		json.Marshal(
			validAck,
		)

	if err != nil {
		t.Fatal(err)
	}

	validRequest :=
		httptest.NewRequest(
			http.MethodPost,
			"/api/v1/agent/execution/fence-ack",
			bytes.NewReader(
				validRaw,
			),
		)

	validRequest =
		validRequest.WithContext(
			context.WithValue(
				validRequest.Context(),
				nodeContextKey,
				model.Node{
					ID: nodeID,

					TenantID: tenantID,
				},
			),
		)

	validRecorder :=
		httptest.NewRecorder()

	app.agentExecutionFenceAck(
		validRecorder,
		validRequest,
	)

	if validRecorder.Code !=
		http.StatusOK {

		t.Fatalf(
			"valid ACK status=%d body=%s",
			validRecorder.Code,
			validRecorder.Body.String(),
		)
	}

	var acknowledged model.ExecutionFenceRequest

	if err :=
		json.NewDecoder(
			validRecorder.Body,
		).Decode(
			&acknowledged,
		); err != nil {

		t.Fatal(err)
	}

	if acknowledged.ID !=
		fenceRequest.ID ||
		acknowledged.State !=
			"acknowledged" {

		t.Fatalf(
			"ACK id=%q state=%q",
			acknowledged.ID,
			acknowledged.State,
		)
	}

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				f.state,
				l.state
			FROM execution_fence_requests f
			JOIN deployment_execution_leases l
				ON l.deployment_id=f.deployment_id
			WHERE f.id=$1::uuid
			`,
			fenceRequest.ID,
		).Scan(
			&requestState,
			&leaseState,
		)

	if err != nil {
		t.Fatal(err)
	}

	if requestState !=
		"acknowledged" ||
		leaseState !=
			"fenced" {

		t.Fatalf(
			"post-ACK request=%q lease=%q want=acknowledged/fenced",
			requestState,
			leaseState,
		)
	}

	// -------------------------------------------------
	// 5. Assignment no longer exposes an acknowledged
	//    fence request.
	// -------------------------------------------------

	assignmentRequest2 :=
		httptest.NewRequest(
			http.MethodGet,
			"/api/v1/agent/assignment",
			nil,
		)

	assignmentRequest2 =
		assignmentRequest2.WithContext(
			context.WithValue(
				assignmentRequest2.Context(),
				nodeContextKey,
				model.Node{
					ID: nodeID,

					TenantID: tenantID,
				},
			),
		)

	assignmentRecorder2 :=
		httptest.NewRecorder()

	app.agentAssignment(
		assignmentRecorder2,
		assignmentRequest2,
	)

	if assignmentRecorder2.Code !=
		http.StatusOK {

		t.Fatalf(
			"post-ACK assignment status=%d body=%s",
			assignmentRecorder2.Code,
			assignmentRecorder2.Body.String(),
		)
	}

	var assignmentAfter model.AgentAssignment

	if err :=
		json.NewDecoder(
			assignmentRecorder2.Body,
		).Decode(
			&assignmentAfter,
		); err != nil {

		t.Fatal(err)
	}

	if assignmentAfter.FenceRequest !=
		nil {

		t.Fatal(
			"acknowledged fence still exposed in assignment",
		)
	}

	// -------------------------------------------------
	// 6. Raw proof must never appear in audit JSON.
	// -------------------------------------------------

	var rawProofLeaks int

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT count(*)
			FROM audit_events
			WHERE node_id=$1::uuid
			  AND position(
					$2::text
					IN payload::text
			      ) > 0
			`,
			nodeID,
			rawLeaseToken,
		).Scan(
			&rawProofLeaks,
		)

	if err != nil {
		t.Fatal(err)
	}

	if rawProofLeaks != 0 {
		t.Fatalf(
			"raw proof leaked into %d audit rows",
			rawProofLeaks,
		)
	}

	var requestedAudits int
	var acknowledgedAudits int
	var fencedAudits int

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				count(*) FILTER (
					WHERE event_type=
						'execution_fence.requested'
				),

				count(*) FILTER (
					WHERE event_type=
						'execution_fence.acknowledged'
				),

				count(*) FILTER (
					WHERE event_type=
						'execution_lease.fenced'
				)

			FROM audit_events
			WHERE node_id=$1::uuid
			  AND payload->>'deployment_id'=$2::text
			`,
			nodeID,
			deploymentID,
		).Scan(
			&requestedAudits,
			&acknowledgedAudits,
			&fencedAudits,
		)

	if err != nil {
		t.Fatal(err)
	}

	if requestedAudits != 1 ||
		acknowledgedAudits != 1 ||
		fencedAudits != 1 {

		t.Fatalf(
			"audit requested=%d acknowledged=%d fenced=%d want=1/1/1",
			requestedAudits,
			acknowledgedAudits,
			fencedAudits,
		)
	}
}
