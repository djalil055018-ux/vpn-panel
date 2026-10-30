package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

var (
	ErrExecutionLeaseConflict = errors.New(
		"execution lease conflict",
	)

	ErrExecutionLeaseExpired = errors.New(
		"execution lease expired",
	)

	ErrExecutionLeaseNotClaimable = errors.New(
		"execution lease not claimable",
	)
)

var (
	ErrExecutionLeaseProofRequired = errors.New(
		"execution lease proof required",
	)

	ErrExecutionLeaseProofIncomplete = errors.New(
		"execution lease proof incomplete",
	)
)

func leaseTTLSeconds(
	ttl time.Duration,
) (int64, error) {
	seconds :=
		int64(
			ttl / time.Second,
		)

	if seconds < 1 {
		return 0,
			fmt.Errorf(
				"execution lease ttl must be >= 1 second",
			)
	}

	return seconds,
		nil
}

func validateLeaseExecutionIdentity(
	execution model.ExecutionAssignment,
	expectedExecutionID string,
	expectedExecutionEpoch int64,
) error {
	if execution.ExecutionID !=
		expectedExecutionID ||
		execution.ExecutionEpoch !=
			expectedExecutionEpoch {

		return fmt.Errorf(
			"%w: generation=%d",
			ErrExecutionIdentityMismatch,
			execution.Generation,
		)
	}

	return nil
}

func (p *Postgres) ClaimExecutionLease(
	ctx context.Context,
	nodeID string,
	execution model.ExecutionAssignment,
	ownerInstanceID string,
	leaseTokenHash string,
	ttl time.Duration,
) (
	time.Time,
	error,
) {
	ttlSeconds, err :=
		leaseTTLSeconds(
			ttl,
		)

	if err != nil {
		return time.Time{},
			err
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return time.Time{},
			err
	}

	defer tx.Rollback(ctx)

	if err :=
		lockExecutionNodeTx(
			ctx,
			tx,
			nodeID,
		); err != nil {

		return time.Time{},
			err
	}

	var tenantID string
	var deploymentStatus string
	var expectedExecutionID string
	var expectedExecutionEpoch int64
	var desiredGeneration int64
	var appliedGeneration int64

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT
				n.tenant_id::text,
				d.status,
				d.execution_id::text,
				d.execution_epoch,
				n.desired_generation,
				n.applied_generation

			FROM deployments d

			JOIN nodes n
				ON n.id = d.node_id

			WHERE d.node_id = $1::uuid
			  AND d.id = $2::uuid
			  AND d.generation = $3::bigint

			FOR UPDATE OF d, n
			`,
			nodeID,
			execution.DeploymentID,
			execution.Generation,
		).Scan(
			&tenantID,
			&deploymentStatus,
			&expectedExecutionID,
			&expectedExecutionEpoch,
			&desiredGeneration,
			&appliedGeneration,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return time.Time{},
			ErrNotFound
	}

	if err != nil {
		return time.Time{},
			err
	}

	if err :=
		validateLeaseExecutionIdentity(
			execution,
			expectedExecutionID,
			expectedExecutionEpoch,
		); err != nil {

		return time.Time{},
			err
	}

	if deploymentStatus != "pending" {
		return time.Time{},
			fmt.Errorf(
				"%w: deployment status=%s",
				ErrExecutionLeaseNotClaimable,
				deploymentStatus,
			)
	}

	if desiredGeneration !=
		execution.Generation ||
		appliedGeneration >=
			execution.Generation {

		return time.Time{},
			fmt.Errorf(
				"%w: desired=%d applied=%d execution=%d",
				ErrExecutionLeaseNotClaimable,
				desiredGeneration,
				appliedGeneration,
				execution.Generation,
			)
	}

	// Expired authority is not physical quiescence. Another generation must be
	// fenced by its owner before a new worker can claim this node.
	var otherActive bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deployment_execution_leases WHERE node_id=$1::uuid AND deployment_id<>$2::uuid AND state='active')`, nodeID, execution.DeploymentID).Scan(&otherActive); err != nil {
		return time.Time{}, err
	}
	if otherActive {
		return time.Time{}, fmt.Errorf("%w: previous physical execution requires fencing", ErrExecutionLeaseConflict)
	}
	_, err =
		tx.Exec(
			ctx,
			`
			INSERT INTO deployment_execution_leases(
				deployment_id,
				node_id,
				generation,
				execution_id,
				execution_epoch,
				state
			)
			VALUES(
				$1::uuid,
				$2::uuid,
				$3::bigint,
				$4::uuid,
				$5::bigint,
				'unclaimed'
			)
			ON CONFLICT(deployment_id)
			DO NOTHING
			`,
			execution.DeploymentID,
			nodeID,
			execution.Generation,
			execution.ExecutionID,
			execution.ExecutionEpoch,
		)

	if err != nil {
		return time.Time{},
			err
	}

	var state string
	var currentOwner string
	var expired bool

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT
				state,

				COALESCE(
					owner_instance_id::text,
					''
				),

				COALESCE(
					lease_expires_at <= now(),
					false
				)

			FROM deployment_execution_leases

			WHERE deployment_id = $1::uuid

			FOR UPDATE
			`,
			execution.DeploymentID,
		).Scan(
			&state,
			&currentOwner,
			&expired,
		)

	if err != nil {
		return time.Time{},
			err
	}

	fenceRequested, err :=
		executionFenceRequestedTx(
			ctx,
			tx,
			execution.DeploymentID,
		)

	if err != nil {
		return time.Time{},
			err
	}

	if fenceRequested {
		return time.Time{},
			fmt.Errorf(
				"%w: execution fence requested",
				ErrExecutionLeaseConflict,
			)
	}

	eventType :=
		"execution_lease.claimed"

	switch state {
	case "unclaimed":

	case "active":
		if expired {
			return time.Time{},
				ErrExecutionLeaseExpired
		}

		if currentOwner !=
			ownerInstanceID {

			return time.Time{},
				ErrExecutionLeaseConflict
		}

		// Same process may retry claim if the previous
		// HTTP response was lost. Reissue the token
		// without changing execution ownership.
		eventType =
			"execution_lease.reissued"

	case "fenced",
		"completed":

		return time.Time{},
			fmt.Errorf(
				"%w: state=%s",
				ErrExecutionLeaseConflict,
				state,
			)

	default:
		return time.Time{},
			fmt.Errorf(
				"unknown execution lease state %q",
				state,
			)
	}

	var leaseExpiresAt time.Time

	err =
		tx.QueryRow(
			ctx,
			`
			UPDATE deployment_execution_leases
			SET
				state = 'active',
				owner_instance_id = $2::uuid,
				lease_token_hash = $3::text,

				claimed_at =
					COALESCE(
						claimed_at,
						now()
					),

				renewed_at = now(),

				lease_expires_at =
					now() +
					(
						$4::bigint *
						interval '1 second'
					),

				updated_at = now()

			WHERE deployment_id = $1::uuid

			RETURNING lease_expires_at
			`,
			execution.DeploymentID,
			ownerInstanceID,
			leaseTokenHash,
			ttlSeconds,
		).Scan(
			&leaseExpiresAt,
		)

	if err != nil {
		return time.Time{},
			err
	}

	_, err =
		tx.Exec(
			ctx,
			`
			INSERT INTO audit_events(
				tenant_id,
				node_id,
				event_type,
				actor_type,
				actor_id,
				payload,
				created_at
			)
			VALUES(
				$1::uuid,
				$2::uuid,
				$3::text,
				'agent',
				$2::text,

				jsonb_build_object(
					'deployment_id',
						$4::text,

					'generation',
						$5::bigint,

					'execution_id',
						$6::text,

					'execution_epoch',
						$7::bigint,

					'owner_instance_id',
						$8::text,

					'lease_expires_at',
						$9::timestamptz
				),

				now()
			)
			`,
			tenantID,
			nodeID,
			eventType,
			execution.DeploymentID,
			execution.Generation,
			execution.ExecutionID,
			execution.ExecutionEpoch,
			ownerInstanceID,
			leaseExpiresAt,
		)

	if err != nil {
		return time.Time{},
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return time.Time{},
			err
	}

	return leaseExpiresAt,
		nil
}

func (p *Postgres) RenewExecutionLease(
	ctx context.Context,
	nodeID string,
	execution model.ExecutionAssignment,
	ownerInstanceID string,
	leaseTokenHash string,
	ttl time.Duration,
) (
	time.Time,
	error,
) {
	ttlSeconds, err :=
		leaseTTLSeconds(
			ttl,
		)

	if err != nil {
		return time.Time{},
			err
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return time.Time{},
			err
	}

	defer tx.Rollback(ctx)

	if err :=
		lockExecutionNodeTx(
			ctx,
			tx,
			nodeID,
		); err != nil {

		return time.Time{},
			err
	}

	var state string
	var currentOwner string
	var currentTokenHash string
	var expired bool

	var deploymentStatus string
	var expectedExecutionID string
	var expectedExecutionEpoch int64

	var desiredGeneration int64
	var appliedGeneration int64

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT
				l.state,
				COALESCE(
					l.owner_instance_id::text,
					''
				),
				COALESCE(
					l.lease_token_hash,
					''
				),
				COALESCE(
					l.lease_expires_at <= now(),
					true
				),

				d.status,
				d.execution_id::text,
				d.execution_epoch,

				n.desired_generation,
				n.applied_generation

			FROM deployment_execution_leases l

			JOIN deployments d
				ON d.id = l.deployment_id

			JOIN nodes n
				ON n.id = l.node_id

			WHERE l.node_id = $1::uuid
			  AND l.deployment_id = $2::uuid
			  AND l.generation = $3::bigint

			FOR UPDATE OF l, d, n
			`,
			nodeID,
			execution.DeploymentID,
			execution.Generation,
		).Scan(
			&state,
			&currentOwner,
			&currentTokenHash,
			&expired,
			&deploymentStatus,
			&expectedExecutionID,
			&expectedExecutionEpoch,
			&desiredGeneration,
			&appliedGeneration,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return time.Time{},
			ErrNotFound
	}

	if err != nil {
		return time.Time{},
			err
	}

	if err :=
		validateLeaseExecutionIdentity(
			execution,
			expectedExecutionID,
			expectedExecutionEpoch,
		); err != nil {

		return time.Time{},
			err
	}

	fenceRequested, err :=
		executionFenceRequestedTx(
			ctx,
			tx,
			execution.DeploymentID,
		)

	if err != nil {
		return time.Time{},
			err
	}

	if fenceRequested {
		return time.Time{},
			fmt.Errorf(
				"%w: execution fence requested",
				ErrExecutionLeaseConflict,
			)
	}

	if state != "active" {
		return time.Time{},
			fmt.Errorf(
				"%w: state=%s",
				ErrExecutionLeaseConflict,
				state,
			)
	}

	if expired {
		return time.Time{},
			ErrExecutionLeaseExpired
	}

	if currentOwner !=
		ownerInstanceID ||
		currentTokenHash !=
			leaseTokenHash {

		return time.Time{},
			ErrExecutionLeaseConflict
	}

	if deploymentStatus != "pending" &&
		deploymentStatus != "applying" {

		return time.Time{},
			fmt.Errorf(
				"%w: deployment status=%s",
				ErrExecutionLeaseConflict,
				deploymentStatus,
			)
	}

	if desiredGeneration !=
		execution.Generation ||
		appliedGeneration >=
			execution.Generation {

		return time.Time{},
			ErrExecutionLeaseConflict
	}

	var leaseExpiresAt time.Time

	err =
		tx.QueryRow(
			ctx,
			`
			UPDATE deployment_execution_leases
			SET
				renewed_at = now(),

				lease_expires_at =
					now() +
					(
						$2::bigint *
						interval '1 second'
					),

				updated_at = now()

			WHERE deployment_id = $1::uuid

			RETURNING lease_expires_at
			`,
			execution.DeploymentID,
			ttlSeconds,
		).Scan(
			&leaseExpiresAt,
		)

	if err != nil {
		return time.Time{},
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return time.Time{},
			err
	}

	return leaseExpiresAt,
		nil
}

func completedLeaseReportAllowed(
	leaseState string,
	reportStatus string,
	changed bool,
) bool {
	if leaseState != "completed" {
		return true
	}

	return !changed &&
		reportStatus != "applying"
}

func deploymentReportHasAnyLeaseProof(
	report model.DeploymentReport,
) bool {
	return report.OwnerInstanceID != "" ||
		report.LeaseToken != ""
}

func validateDeploymentLeaseProofTx(
	ctx context.Context,
	tx pgx.Tx,
	nodeID string,
	deploymentID string,
	report model.DeploymentReport,
) (
	string,
	bool,
	error,
) {
	hasOwner :=
		report.OwnerInstanceID != ""

	hasToken :=
		report.LeaseToken != ""

	if hasOwner != hasToken {
		return "",
			false,
			ErrExecutionLeaseProofIncomplete
	}

	var state string
	var ownerInstanceID string
	var leaseTokenHash string
	var expired bool

	err :=
		tx.QueryRow(
			ctx,
			`
			SELECT
				state,

				COALESCE(
					owner_instance_id::text,
					''
				),

				COALESCE(
					lease_token_hash,
					''
				),

				COALESCE(
					lease_expires_at <= now(),
					true
				)

			FROM deployment_execution_leases

			WHERE deployment_id = $1::uuid
			  AND node_id = $2::uuid
			  AND generation = $3::bigint
			  AND execution_id = $4::uuid
			  AND execution_epoch = $5::bigint

			FOR UPDATE
			`,
			deploymentID,
			nodeID,
			report.Generation,
			report.ExecutionID,
			report.ExecutionEpoch,
		).Scan(
			&state,
			&ownerInstanceID,
			&leaseTokenHash,
			&expired,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		// Temporary D4B backward compatibility:
		// a deployment with no lease row is still
		// accepted from Agent 0.2.7.
		if !deploymentReportHasAnyLeaseProof(
			report,
		) {
			return "",
				false,
				nil
		}

		return "",
			false,
			ErrExecutionLeaseConflict
	}

	if err != nil {
		return "",
			false,
			err
	}

	if !hasOwner || !hasToken {
		return state,
			true,
			ErrExecutionLeaseProofRequired
	}

	if ownerInstanceID !=
		report.OwnerInstanceID {

		return state,
			true,
			ErrExecutionLeaseConflict
	}

	reportTokenHash :=
		security.HashToken(
			report.LeaseToken,
		)

	if !security.EqualSecret(
		leaseTokenHash,
		reportTokenHash,
	) {
		return state,
			true,
			ErrExecutionLeaseConflict
	}

	switch state {
	case "active":
		if expired {
			return state,
				true,
				ErrExecutionLeaseExpired
		}

	case "completed":
		// Allowed only for idempotent terminal
		// report retry. The caller decides whether
		// the deployment transition is a no-op.

	default:
		return state,
			true,
			fmt.Errorf(
				"%w: state=%s",
				ErrExecutionLeaseConflict,
				state,
			)
	}

	return state,
		true,
		nil
}

func completeDeploymentExecutionLeaseTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	nodeID string,
	deploymentID string,
	report model.DeploymentReport,
) error {
	var completedAt time.Time

	err :=
		tx.QueryRow(
			ctx,
			`
			UPDATE deployment_execution_leases
			SET
				state = 'completed',
				completed_at = now(),
				updated_at = now()

			WHERE deployment_id = $1::uuid
			  AND node_id = $2::uuid
			  AND generation = $3::bigint
			  AND execution_id = $4::uuid
			  AND execution_epoch = $5::bigint
			  AND state = 'active'

			RETURNING completed_at
			`,
			deploymentID,
			nodeID,
			report.Generation,
			report.ExecutionID,
			report.ExecutionEpoch,
		).Scan(
			&completedAt,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return ErrExecutionLeaseConflict
	}

	if err != nil {
		return err
	}

	_, err =
		tx.Exec(
			ctx,
			`
			INSERT INTO audit_events(
				tenant_id,
				node_id,
				event_type,
				actor_type,
				actor_id,
				payload,
				created_at
			)
			VALUES(
				$1::uuid,
				$2::uuid,
				'execution_lease.completed',
				'agent',
				$2::text,

				jsonb_build_object(
					'deployment_id',
						$3::text,

					'generation',
						$4::bigint,

					'execution_id',
						$5::text,

					'execution_epoch',
						$6::bigint,

					'owner_instance_id',
						$7::text,

					'completed_at',
						$8::timestamptz
				),

				now()
			)
			`,
			tenantID,
			nodeID,
			deploymentID,
			report.Generation,
			report.ExecutionID,
			report.ExecutionEpoch,
			report.OwnerInstanceID,
			completedAt,
		)

	return err
}
