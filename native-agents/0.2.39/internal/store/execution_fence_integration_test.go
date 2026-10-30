//go:build integration

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestExecutionFenceStoreE2E(
	t *testing.T,
) {
	dsn := os.Getenv("DATABASE_URL")

	if dsn == "" {
		t.Fatal(
			"DATABASE_URL is required for integration test",
		)
	}

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			30*time.Second,
		)

	defer cancel()

	db, err :=
		NewPostgres(
			ctx,
			dsn,
		)

	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	var tenantID string
	var nodeID string
	var deploymentID string
	var executionID string
	var executionEpoch int64

	tenantName :=
		fmt.Sprintf(
			"D4C1B-FENCE-%d",
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

	// Cleanup is isolated by tenant cascade.
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
			"D4C1B-TEMP-NODE",
		).Scan(
			&nodeID,
		)

	if err != nil {
		t.Fatal(err)
	}

	// Let the existing deployment execution allocator create
	// execution_id and execution_epoch.
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

	if executionEpoch < 1 {
		t.Fatalf(
			"execution_epoch=%d want >=1",
			executionEpoch,
		)
	}

	execution :=
		model.ExecutionAssignment{
			DeploymentID: deploymentID,

			Generation: 1,

			ExecutionID: executionID,

			ExecutionEpoch: executionEpoch,
		}

	var ownerInstanceID string
	var wrongOwnerInstanceID string

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				gen_random_uuid()::text,
				gen_random_uuid()::text
			`,
		).Scan(
			&ownerInstanceID,
			&wrongOwnerInstanceID,
		)

	if err != nil {
		t.Fatal(err)
	}

	rawLeaseToken, err :=
		security.NewToken(48)

	if err != nil {
		t.Fatal(err)
	}

	leaseTokenHash :=
		security.HashToken(
			rawLeaseToken,
		)

	// Deliberately create an already-expired active lease.
	//
	// This models:
	// authority expired,
	// physical quiescence not yet proven.
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
				$3::bigint,
				$4::uuid,
				$5::bigint,
				'active',
				$6::uuid,
				$7::text,
				now() - interval '2 minutes',
				now() - interval '90 seconds',
				now() - interval '30 seconds'
			)
			`,
			deploymentID,
			nodeID,
			execution.Generation,
			execution.ExecutionID,
			execution.ExecutionEpoch,
			ownerInstanceID,
			leaseTokenHash,
		)

	if err != nil {
		t.Fatal(err)
	}

	const fenceReason = "integration test physical quiescence"

	// 1. Create request.
	request, err :=
		db.CreateExecutionFenceRequest(
			ctx,
			nodeID,
			execution,
			fenceReason,
		)

	if err != nil {
		t.Fatal(err)
	}

	if request.State !=
		"requested" {

		t.Fatalf(
			"request state=%q want=requested",
			request.State,
		)
	}

	if request.TargetOwnerInstanceID !=
		ownerInstanceID {

		t.Fatalf(
			"target owner=%q want=%q",
			request.TargetOwnerInstanceID,
			ownerInstanceID,
		)
	}

	// Creating a request MUST NOT claim physical quiescence.
	var leaseState string
	var expired bool
	var fencedAtPresent bool

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				state,
				lease_expires_at <= now(),
				fenced_at IS NOT NULL
			FROM deployment_execution_leases
			WHERE deployment_id=$1::uuid
			`,
			deploymentID,
		).Scan(
			&leaseState,
			&expired,
			&fencedAtPresent,
		)

	if err != nil {
		t.Fatal(err)
	}

	if leaseState !=
		"active" {

		t.Fatalf(
			"lease state after request=%q want=active",
			leaseState,
		)
	}

	if !expired {
		t.Fatal(
			"fixture lease should already be expired",
		)
	}

	if fencedAtPresent {
		t.Fatal(
			"fence request incorrectly set fenced_at before ACK",
		)
	}

	// 2. Identical create is idempotent.
	duplicateRequest, err :=
		db.CreateExecutionFenceRequest(
			ctx,
			nodeID,
			execution,
			fenceReason,
		)

	if err != nil {
		t.Fatal(err)
	}

	if duplicateRequest.ID !=
		request.ID {

		t.Fatalf(
			"duplicate request id=%q want=%q",
			duplicateRequest.ID,
			request.ID,
		)
	}

	// 3. Wrong owner cannot ACK.
	_, err =
		db.AcknowledgeExecutionFenceRequest(
			ctx,
			nodeID,
			request.ID,
			execution,
			wrongOwnerInstanceID,
			leaseTokenHash,
		)

	if !errors.Is(
		err,
		ErrExecutionFenceConflict,
	) {
		t.Fatalf(
			"wrong owner error=%v want ErrExecutionFenceConflict",
			err,
		)
	}

	// 4. Correct owner but wrong proof cannot ACK.
	wrongProofHash :=
		security.HashToken(
			"wrong-fence-proof",
		)

	_, err =
		db.AcknowledgeExecutionFenceRequest(
			ctx,
			nodeID,
			request.ID,
			execution,
			ownerInstanceID,
			wrongProofHash,
		)

	if !errors.Is(
		err,
		ErrExecutionFenceProofInvalid,
	) {
		t.Fatalf(
			"wrong proof error=%v want ErrExecutionFenceProofInvalid",
			err,
		)
	}

	// Failed ACKs must leave both rows untouched.
	var requestState string

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT state
			FROM execution_fence_requests
			WHERE id=$1::uuid
			`,
			request.ID,
		).Scan(
			&requestState,
		)

	if err != nil {
		t.Fatal(err)
	}

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT state
			FROM deployment_execution_leases
			WHERE deployment_id=$1::uuid
			`,
			deploymentID,
		).Scan(
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
			"failed ACK mutated state request=%q lease=%q",
			requestState,
			leaseState,
		)
	}

	// 5. Correct owner + proof ACKs even though lease expired.
	acknowledged, err :=
		db.AcknowledgeExecutionFenceRequest(
			ctx,
			nodeID,
			request.ID,
			execution,
			ownerInstanceID,
			leaseTokenHash,
		)

	if err != nil {
		t.Fatal(err)
	}

	if acknowledged.State !=
		"acknowledged" {

		t.Fatalf(
			"ACK state=%q want=acknowledged",
			acknowledged.State,
		)
	}

	if acknowledged.AcknowledgedAt ==
		nil {

		t.Fatal(
			"acknowledged_at is nil",
		)
	}

	if acknowledged.AcknowledgedByInstanceID !=
		ownerInstanceID {

		t.Fatalf(
			"ack owner=%q want=%q",
			acknowledged.AcknowledgedByInstanceID,
			ownerInstanceID,
		)
	}

	var fencingReason string

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				state,
				COALESCE(
					fencing_reason,
					''
				),
				fenced_at IS NOT NULL
			FROM deployment_execution_leases
			WHERE deployment_id=$1::uuid
			`,
			deploymentID,
		).Scan(
			&leaseState,
			&fencingReason,
			&fencedAtPresent,
		)

	if err != nil {
		t.Fatal(err)
	}

	if leaseState !=
		"fenced" {

		t.Fatalf(
			"lease state=%q want=fenced",
			leaseState,
		)
	}

	if !fencedAtPresent {
		t.Fatal(
			"fenced_at was not recorded",
		)
	}

	if fencingReason !=
		fenceReason {

		t.Fatalf(
			"fencing reason=%q want=%q",
			fencingReason,
			fenceReason,
		)
	}

	// 6. Same ACK can be retried after lost HTTP response.
	duplicateACK, err :=
		db.AcknowledgeExecutionFenceRequest(
			ctx,
			nodeID,
			request.ID,
			execution,
			ownerInstanceID,
			leaseTokenHash,
		)

	if err != nil {
		t.Fatal(err)
	}

	if duplicateACK.ID !=
		request.ID ||
		duplicateACK.State !=
			"acknowledged" {

		t.Fatalf(
			"duplicate ACK id=%q state=%q",
			duplicateACK.ID,
			duplicateACK.State,
		)
	}

	// 7. Audit events must be exactly-once despite retries.
	var requestedAudits int
	var acknowledgedAudits int
	var fencedAudits int

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				count(*) FILTER (
					WHERE event_type =
						'execution_fence.requested'
				),
				count(*) FILTER (
					WHERE event_type =
						'execution_fence.acknowledged'
				),
				count(*) FILTER (
					WHERE event_type =
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
			"audit counts requested=%d acknowledged=%d fenced=%d want=1/1/1",
			requestedAudits,
			acknowledgedAudits,
			fencedAudits,
		)
	}

	// Raw RAM-only credential must never appear in audit JSON.
	var leakedRawProof int

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
			&leakedRawProof,
		)

	if err != nil {
		t.Fatal(err)
	}

	if leakedRawProof != 0 {
		t.Fatalf(
			"raw fence proof leaked into %d audit rows",
			leakedRawProof,
		)
	}

	// One physical execution -> one fence request.
	var fenceRows int

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT count(*)
			FROM execution_fence_requests
			WHERE deployment_id=$1::uuid
			`,
			deploymentID,
		).Scan(
			&fenceRows,
		)

	if err != nil {
		t.Fatal(err)
	}

	if fenceRows != 1 {
		t.Fatalf(
			"fence request rows=%d want=1",
			fenceRows,
		)
	}
}

func TestExecutionFenceRequestedRevokesLeaseAuthorityE2E(
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
		NewPostgres(
			ctx,
			dsn,
		)

	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	var tenantID string
	var nodeID string
	var deploymentID string
	var executionID string
	var executionEpoch int64

	tenantName :=
		fmt.Sprintf(
			"D4C1C-REVOKE-%d",
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
			"D4C1C-TEMP-NODE",
		).Scan(
			&nodeID,
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
				'pending',
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

	// Establish valid execution authority.
	_, err =
		db.ClaimExecutionLease(
			ctx,
			nodeID,
			execution,
			ownerInstanceID,
			leaseHash,
			60*time.Second,
		)

	if err != nil {
		t.Fatal(err)
	}

	// A valid lease renew works before fencing starts.
	_, err =
		db.RenewExecutionLease(
			ctx,
			nodeID,
			execution,
			ownerInstanceID,
			leaseHash,
			60*time.Second,
		)

	if err != nil {
		t.Fatalf(
			"renew before fence failed: %v",
			err,
		)
	}

	// Create the revocation barrier.
	request, err :=
		db.CreateExecutionFenceRequest(
			ctx,
			nodeID,
			execution,
			"integration revocation barrier",
		)

	if err != nil {
		t.Fatal(err)
	}

	if request.State !=
		"requested" {

		t.Fatalf(
			"request state=%q want=requested",
			request.State,
		)
	}

	// Claim/reissue after request MUST be rejected.
	newRawToken, err :=
		security.NewToken(48)

	if err != nil {
		t.Fatal(err)
	}

	newHash :=
		security.HashToken(
			newRawToken,
		)

	_, err =
		db.ClaimExecutionLease(
			ctx,
			nodeID,
			execution,
			ownerInstanceID,
			newHash,
			60*time.Second,
		)

	if !errors.Is(
		err,
		ErrExecutionLeaseConflict,
	) {
		t.Fatalf(
			"claim after fence error=%v want ErrExecutionLeaseConflict",
			err,
		)
	}

	// Renew after request MUST also be rejected.
	_, err =
		db.RenewExecutionLease(
			ctx,
			nodeID,
			execution,
			ownerInstanceID,
			leaseHash,
			60*time.Second,
		)

	if !errors.Is(
		err,
		ErrExecutionLeaseConflict,
	) {
		t.Fatalf(
			"renew after fence error=%v want ErrExecutionLeaseConflict",
			err,
		)
	}

	// Failed claim must not rotate the proof hash.
	var storedHash string
	var leaseState string
	var requestState string

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				state,
				lease_token_hash
			FROM deployment_execution_leases
			WHERE deployment_id=$1::uuid
			`,
			deploymentID,
		).Scan(
			&leaseState,
			&storedHash,
		)

	if err != nil {
		t.Fatal(err)
	}

	if leaseState !=
		"active" {

		t.Fatalf(
			"lease state=%q want=active",
			leaseState,
		)
	}

	if storedHash !=
		leaseHash {

		t.Fatal(
			"rejected claim rotated lease proof",
		)
	}

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT state
			FROM execution_fence_requests
			WHERE id=$1::uuid
			`,
			request.ID,
		).Scan(
			&requestState,
		)

	if err != nil {
		t.Fatal(err)
	}

	if requestState !=
		"requested" {

		t.Fatalf(
			"request state=%q want=requested",
			requestState,
		)
	}
}

func TestExecutionFenceRequestedRevokesDeploymentReportsE2E(
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
		NewPostgres(
			ctx,
			dsn,
		)

	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	var tenantID string
	var nodeID string
	var deploymentID string
	var executionID string
	var executionEpoch int64

	tenantName :=
		fmt.Sprintf(
			"D4C1D-REPORT-%d",
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
			"D4C1D-TEMP-NODE",
		).Scan(
			&nodeID,
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
				'pending',
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
		db.ClaimExecutionLease(
			ctx,
			nodeID,
			execution,
			ownerInstanceID,
			leaseHash,
			60*time.Second,
		)

	if err != nil {
		t.Fatal(err)
	}

	// Establish the live applying state before fencing.
	applyingReport :=
		model.DeploymentReport{
			Generation: 1,

			DeploymentID: deploymentID,

			ExecutionID: executionID,

			ExecutionEpoch: executionEpoch,

			OwnerInstanceID: ownerInstanceID,

			LeaseToken: rawLeaseToken,

			Status: "applying",

			ReportedAt: time.Now().UTC(),
		}

	if err :=
		db.SaveDeploymentReport(
			ctx,
			nodeID,
			applyingReport,
		); err != nil {

		t.Fatalf(
			"initial applying report failed: %v",
			err,
		)
	}

	request, err :=
		db.CreateExecutionFenceRequest(
			ctx,
			nodeID,
			execution,
			"integration deployment report barrier",
		)

	if err != nil {
		t.Fatal(err)
	}

	if request.State !=
		"requested" {

		t.Fatalf(
			"request state=%q want=requested",
			request.State,
		)
	}

	// Every late execution report must now be rejected.
	tests :=
		[]struct {
			status      string
			appliedCore string
			errorText   string
		}{
			{
				status: "applying",
			},
			{
				status: "healthy",

				appliedCore: "26.7.28",
			},
			{
				status: "failed",

				errorText: "late failed report",
			},
			{
				status: "rolled_back",

				appliedCore: "26.7.28",

				errorText: "late rollback report",
			},
		}

	for _, tc := range tests {

		report :=
			model.DeploymentReport{
				Generation: 1,

				DeploymentID: deploymentID,

				ExecutionID: executionID,

				ExecutionEpoch: executionEpoch,

				OwnerInstanceID: ownerInstanceID,

				LeaseToken: rawLeaseToken,

				Status: tc.status,

				AppliedCoreVersion: tc.appliedCore,

				ErrorMessage: tc.errorText,

				ReportedAt: time.Now().UTC(),
			}

		err :=
			db.SaveDeploymentReport(
				ctx,
				nodeID,
				report,
			)

		if !errors.Is(
			err,
			ErrExecutionLeaseConflict,
		) {
			t.Fatalf(
				"late %s report error=%v want ErrExecutionLeaseConflict",
				tc.status,
				err,
			)
		}
	}

	// Nothing from the rejected reports may have mutated
	// deployment, node generation, lease, or fence request.
	var deploymentStatus string
	var appliedGeneration int64
	var leaseState string
	var requestState string

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				d.status,
				n.applied_generation,
				l.state,
				f.state
			FROM deployments d
			JOIN nodes n
				ON n.id=d.node_id
			JOIN deployment_execution_leases l
				ON l.deployment_id=d.id
			JOIN execution_fence_requests f
				ON f.deployment_id=d.id
			WHERE d.id=$1::uuid
			`,
			deploymentID,
		).Scan(
			&deploymentStatus,
			&appliedGeneration,
			&leaseState,
			&requestState,
		)

	if err != nil {
		t.Fatal(err)
	}

	if deploymentStatus !=
		"applying" {

		t.Fatalf(
			"deployment status=%q want=applying",
			deploymentStatus,
		)
	}

	if appliedGeneration != 0 {
		t.Fatalf(
			"applied_generation=%d want=0",
			appliedGeneration,
		)
	}

	if leaseState !=
		"active" {

		t.Fatalf(
			"lease state=%q want=active",
			leaseState,
		)
	}

	if requestState !=
		"requested" {

		t.Fatalf(
			"fence request state=%q want=requested",
			requestState,
		)
	}

	// Only the original pre-fence applying report may exist.
	var applyingAudits int
	var terminalAudits int

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				count(*) FILTER (
					WHERE event_type='deployment.applying'
				),
				count(*) FILTER (
					WHERE event_type IN (
						'deployment.healthy',
						'deployment.failed',
						'deployment.rolled_back'
					)
				)
			FROM audit_events
			WHERE node_id=$1::uuid
			  AND payload->>'deployment_id'=$2::text
			`,
			nodeID,
			deploymentID,
		).Scan(
			&applyingAudits,
			&terminalAudits,
		)

	if err != nil {
		t.Fatal(err)
	}

	if applyingAudits != 1 {
		t.Fatalf(
			"deployment.applying audits=%d want=1",
			applyingAudits,
		)
	}

	if terminalAudits != 0 {
		t.Fatalf(
			"terminal deployment audits=%d want=0",
			terminalAudits,
		)
	}

	// Quiescence ACK is now the only valid path forward.
	acknowledged, err :=
		db.AcknowledgeExecutionFenceRequest(
			ctx,
			nodeID,
			request.ID,
			execution,
			ownerInstanceID,
			leaseHash,
		)

	if err != nil {
		t.Fatal(err)
	}

	if acknowledged.State !=
		"acknowledged" {

		t.Fatalf(
			"ACK state=%q want=acknowledged",
			acknowledged.State,
		)
	}

	err =
		db.Pool.QueryRow(
			ctx,
			`
			SELECT
				l.state,
				f.state
			FROM deployment_execution_leases l
			JOIN execution_fence_requests f
				ON f.deployment_id=l.deployment_id
			WHERE l.deployment_id=$1::uuid
			`,
			deploymentID,
		).Scan(
			&leaseState,
			&requestState,
		)

	if err != nil {
		t.Fatal(err)
	}

	if leaseState !=
		"fenced" ||
		requestState !=
			"acknowledged" {

		t.Fatalf(
			"post-ACK lease=%q request=%q want=fenced/acknowledged",
			leaseState,
			requestState,
		)
	}
}
