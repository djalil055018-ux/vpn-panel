package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

var (
	ErrExecutionFenceConflict = errors.New(
		"execution fence conflict",
	)

	ErrExecutionFenceNotRequestable = errors.New(
		"execution fence not requestable",
	)

	ErrExecutionFenceProofInvalid = errors.New(
		"execution fence proof invalid",
	)
)

type executionFenceRow interface {
	Scan(dest ...any) error
}

func scanExecutionFenceRequest(
	row executionFenceRow,
) (
	model.ExecutionFenceRequest,
	error,
) {
	var result model.ExecutionFenceRequest

	err :=
		row.Scan(
			&result.ID,
			&result.TenantID,
			&result.NodeID,
			&result.DeploymentID,
			&result.Generation,
			&result.ExecutionID,
			&result.ExecutionEpoch,
			&result.State,
			&result.TargetOwnerInstanceID,
			&result.Reason,
			&result.RequestedAt,
			&result.AcknowledgedAt,
			&result.AcknowledgedByInstanceID,
			&result.CancelledAt,
			&result.CreatedAt,
			&result.UpdatedAt,
		)

	return result, err
}

const executionFenceRequestColumns = `
	id::text,
	tenant_id::text,
	node_id::text,
	deployment_id::text,
	generation,
	execution_id::text,
	execution_epoch,
	state,
	target_owner_instance_id::text,
	reason,
	requested_at,
	acknowledged_at,
	COALESCE(
		acknowledged_by_instance_id::text,
		''
	),
	cancelled_at,
	created_at,
	updated_at
`

func lockExecutionNodeTx(
	ctx context.Context,
	tx pgx.Tx,
	nodeID string,
) error {
	_, err :=
		tx.Exec(
			ctx,
			`
			SELECT pg_advisory_xact_lock(
				hashtextextended(
					$1::text,
					0
				)
			)
			`,
			nodeID,
		)

	return err
}

func executionFenceRequestedTx(
	ctx context.Context,
	tx pgx.Tx,
	deploymentID string,
) (
	bool,
	error,
) {
	var requested bool

	err :=
		tx.QueryRow(
			ctx,
			`
			SELECT EXISTS(
				SELECT 1
				FROM execution_fence_requests
				WHERE deployment_id = $1::uuid
				  AND state = 'requested'
			)
			`,
			deploymentID,
		).Scan(
			&requested,
		)

	return requested,
		err
}

func sameFenceExecution(
	request model.ExecutionFenceRequest,
	execution model.ExecutionAssignment,
) bool {
	return request.DeploymentID ==
		execution.DeploymentID &&
		request.Generation ==
			execution.Generation &&
		request.ExecutionID ==
			execution.ExecutionID &&
		request.ExecutionEpoch ==
			execution.ExecutionEpoch
}

func (p *Postgres) CreateExecutionFenceRequest(
	ctx context.Context,
	nodeID string,
	execution model.ExecutionAssignment,
	reason string,
) (
	model.ExecutionFenceRequest,
	error,
) {
	nodeID =
		strings.TrimSpace(
			nodeID,
		)

	reason =
		strings.TrimSpace(
			reason,
		)

	if nodeID == "" ||
		execution.DeploymentID == "" ||
		execution.Generation < 1 ||
		execution.ExecutionID == "" ||
		execution.ExecutionEpoch < 1 ||
		reason == "" {

		return model.ExecutionFenceRequest{},
			ErrExecutionFenceNotRequestable
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	defer tx.Rollback(ctx)

	// Serialize fencing decisions for one node.
	_, err =
		tx.Exec(
			ctx,
			`
			SELECT pg_advisory_xact_lock(
				hashtextextended(
					$1::text,
					0
				)
			)
			`,
			nodeID,
		)

	if err != nil {
		return model.ExecutionFenceRequest{},
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
		return model.ExecutionFenceRequest{},
			ErrNotFound
	}

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	if err :=
		validateLeaseExecutionIdentity(
			execution,
			expectedExecutionID,
			expectedExecutionEpoch,
		); err != nil {

		return model.ExecutionFenceRequest{},
			err
	}

	if deploymentStatus != "pending" &&
		deploymentStatus != "applying" {

		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: deployment status=%s",
				ErrExecutionFenceNotRequestable,
				deploymentStatus,
			)
	}

	if desiredGeneration <
		execution.Generation ||
		appliedGeneration >=
			execution.Generation {

		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: desired=%d applied=%d generation=%d",
				ErrExecutionFenceNotRequestable,
				desiredGeneration,
				appliedGeneration,
				execution.Generation,
			)
	}

	var leaseState string
	var ownerInstanceID string
	var leaseTokenHash string

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
					lease_token_hash,
					''
				)
			FROM deployment_execution_leases
			WHERE deployment_id = $1::uuid
			  AND node_id = $2::uuid
			  AND generation = $3::bigint
			  AND execution_id = $4::uuid
			  AND execution_epoch = $5::bigint
			FOR UPDATE
			`,
			execution.DeploymentID,
			nodeID,
			execution.Generation,
			execution.ExecutionID,
			execution.ExecutionEpoch,
		).Scan(
			&leaseState,
			&ownerInstanceID,
			&leaseTokenHash,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: execution lease not found",
				ErrExecutionFenceNotRequestable,
			)
	}

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	if leaseState != "active" {
		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: lease state=%s",
				ErrExecutionFenceNotRequestable,
				leaseState,
			)
	}

	if ownerInstanceID == "" ||
		leaseTokenHash == "" {

		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: active lease has no physical owner proof",
				ErrExecutionFenceNotRequestable,
			)
	}

	// An identical outstanding request is idempotent.
	existing, existingErr :=
		scanExecutionFenceRequest(
			tx.QueryRow(
				ctx,
				`
				SELECT
				`+executionFenceRequestColumns+`
				FROM execution_fence_requests
				WHERE deployment_id = $1::uuid
				  AND state = 'requested'
				FOR UPDATE
				`,
				execution.DeploymentID,
			),
		)

	if existingErr == nil {
		if sameFenceExecution(
			existing,
			execution,
		) &&
			existing.TargetOwnerInstanceID ==
				ownerInstanceID &&
			existing.Reason ==
				reason {

			return existing,
				nil
		}

		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict
	}

	if !errors.Is(
		existingErr,
		pgx.ErrNoRows,
	) {
		return model.ExecutionFenceRequest{},
			existingErr
	}

	request, err :=
		scanExecutionFenceRequest(
			tx.QueryRow(
				ctx,
				`
				INSERT INTO execution_fence_requests(
					tenant_id,
					node_id,
					deployment_id,
					generation,
					execution_id,
					execution_epoch,
					state,
					target_owner_instance_id,
					reason
				)
				VALUES(
					$1::uuid,
					$2::uuid,
					$3::uuid,
					$4::bigint,
					$5::uuid,
					$6::bigint,
					'requested',
					$7::uuid,
					$8::text
				)
				RETURNING
					`+executionFenceRequestColumns+`
				`,
				tenantID,
				nodeID,
				execution.DeploymentID,
				execution.Generation,
				execution.ExecutionID,
				execution.ExecutionEpoch,
				ownerInstanceID,
				reason,
			),
		)

	if err != nil {
		return model.ExecutionFenceRequest{},
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
				'execution_fence.requested',
				'admin',
				'control-plane',
				jsonb_build_object(
					'fence_request_id',
						$3::text,
					'deployment_id',
						$4::text,
					'generation',
						$5::bigint,
					'execution_id',
						$6::text,
					'execution_epoch',
						$7::bigint,
					'target_owner_instance_id',
						$8::text,
					'reason',
						$9::text
				),
				now()
			)
			`,
			tenantID,
			nodeID,
			request.ID,
			execution.DeploymentID,
			execution.Generation,
			execution.ExecutionID,
			execution.ExecutionEpoch,
			ownerInstanceID,
			reason,
		)

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return model.ExecutionFenceRequest{},
			err
	}

	return request,
		nil
}

func (p *Postgres) AcknowledgeExecutionFenceRequest(
	ctx context.Context,
	nodeID string,
	requestID string,
	execution model.ExecutionAssignment,
	ownerInstanceID string,
	fenceProofTokenHash string,
) (
	model.ExecutionFenceRequest,
	error,
) {
	nodeID =
		strings.TrimSpace(
			nodeID,
		)

	requestID =
		strings.TrimSpace(
			requestID,
		)

	ownerInstanceID =
		strings.TrimSpace(
			ownerInstanceID,
		)

	fenceProofTokenHash =
		strings.TrimSpace(
			fenceProofTokenHash,
		)

	if nodeID == "" ||
		requestID == "" ||
		ownerInstanceID == "" ||
		fenceProofTokenHash == "" ||
		execution.DeploymentID == "" ||
		execution.Generation < 1 ||
		execution.ExecutionID == "" ||
		execution.ExecutionEpoch < 1 {

		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict
	}

	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	defer tx.Rollback(ctx)

	request, err :=
		scanExecutionFenceRequest(
			tx.QueryRow(
				ctx,
				`
				SELECT
					`+executionFenceRequestColumns+`
				FROM execution_fence_requests
				WHERE id = $1::uuid
				  AND node_id = $2::uuid
				FOR UPDATE
				`,
				requestID,
				nodeID,
			),
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.ExecutionFenceRequest{},
			ErrNotFound
	}

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	if !sameFenceExecution(
		request,
		execution,
	) {
		return model.ExecutionFenceRequest{},
			ErrExecutionIdentityMismatch
	}

	if request.TargetOwnerInstanceID !=
		ownerInstanceID {

		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict
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
		return model.ExecutionFenceRequest{},
			ErrNotFound
	}

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	if tenantID !=
		request.TenantID {

		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict
	}

	if err :=
		validateLeaseExecutionIdentity(
			execution,
			expectedExecutionID,
			expectedExecutionEpoch,
		); err != nil {

		return model.ExecutionFenceRequest{},
			err
	}

	var leaseState string
	var leaseOwnerInstanceID string
	var leaseTokenHash string
	var fencingReason string

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
					lease_token_hash,
					''
				),
				COALESCE(
					fencing_reason,
					''
				)
			FROM deployment_execution_leases
			WHERE deployment_id = $1::uuid
			  AND node_id = $2::uuid
			  AND generation = $3::bigint
			  AND execution_id = $4::uuid
			  AND execution_epoch = $5::bigint
			FOR UPDATE
			`,
			execution.DeploymentID,
			nodeID,
			execution.Generation,
			execution.ExecutionID,
			execution.ExecutionEpoch,
		).Scan(
			&leaseState,
			&leaseOwnerInstanceID,
			&leaseTokenHash,
			&fencingReason,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict
	}

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	if leaseOwnerInstanceID !=
		ownerInstanceID {

		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict
	}

	if !security.EqualSecret(
		leaseTokenHash,
		fenceProofTokenHash,
	) {
		return model.ExecutionFenceRequest{},
			ErrExecutionFenceProofInvalid
	}

	switch request.State {
	case "acknowledged":
		// Idempotent retry is allowed only for the same
		// execution owner and the same already-fenced lease.
		if request.AcknowledgedByInstanceID !=
			ownerInstanceID ||
			leaseState != "fenced" ||
			fencingReason !=
				request.Reason {

			return model.ExecutionFenceRequest{},
				ErrExecutionFenceConflict
		}

		return request,
			nil

	case "cancelled":
		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict

	case "requested":

	default:
		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: request state=%s",
				ErrExecutionFenceConflict,
				request.State,
			)
	}

	if deploymentStatus != "pending" &&
		deploymentStatus != "applying" {

		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: deployment status=%s",
				ErrExecutionFenceConflict,
				deploymentStatus,
			)
	}

	if desiredGeneration <
		execution.Generation ||
		appliedGeneration >=
			execution.Generation {

		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: desired=%d applied=%d generation=%d",
				ErrExecutionFenceConflict,
				desiredGeneration,
				appliedGeneration,
				execution.Generation,
			)
	}

	// Expiry is intentionally NOT checked here.
	//
	// An expired active lease means execution authority has
	// ended, but physical quiescence has not yet been proven.
	// The ACK itself is the quiescence proof.
	if leaseState != "active" {
		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"%w: lease state=%s",
				ErrExecutionFenceConflict,
				leaseState,
			)
	}

	request, err =
		scanExecutionFenceRequest(
			tx.QueryRow(
				ctx,
				`
				UPDATE execution_fence_requests
				SET
					state = 'acknowledged',
					acknowledged_at = now(),
					acknowledged_by_instance_id =
						$2::uuid,
					updated_at = now()
				WHERE id = $1::uuid
				  AND state = 'requested'
				RETURNING
					`+executionFenceRequestColumns+`
				`,
				request.ID,
				ownerInstanceID,
			),
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict
	}

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	var fencedAt any

	err =
		tx.QueryRow(
			ctx,
			`
			UPDATE deployment_execution_leases
			SET
				state = 'fenced',
				fenced_at = now(),
				fencing_reason = $2::text,
				updated_at = now()
			WHERE deployment_id = $1::uuid
			  AND state = 'active'
			RETURNING fenced_at
			`,
			execution.DeploymentID,
			request.Reason,
		).Scan(
			&fencedAt,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.ExecutionFenceRequest{},
			ErrExecutionFenceConflict
	}

	if err != nil {
		return model.ExecutionFenceRequest{},
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
			VALUES
			(
				$1::uuid,
				$2::uuid,
				'execution_fence.acknowledged',
				'agent',
				$2::text,
				jsonb_build_object(
					'fence_request_id',
						$3::text,
					'deployment_id',
						$4::text,
					'generation',
						$5::bigint,
					'execution_id',
						$6::text,
					'execution_epoch',
						$7::bigint,
					'owner_instance_id',
						$8::text
				),
				now()
			),
			(
				$1::uuid,
				$2::uuid,
				'execution_lease.fenced',
				'agent',
				$2::text,
				jsonb_build_object(
					'fence_request_id',
						$3::text,
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
					'reason',
						$9::text
				),
				now()
			)
			`,
			tenantID,
			nodeID,
			request.ID,
			execution.DeploymentID,
			execution.Generation,
			execution.ExecutionID,
			execution.ExecutionEpoch,
			ownerInstanceID,
			request.Reason,
		)

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return model.ExecutionFenceRequest{},
			err
	}

	return request,
		nil
}

func (p *Postgres) CreateExecutionFenceRequestForGeneration(
	ctx context.Context,
	nodeID string,
	generation int64,
	reason string,
) (
	model.ExecutionFenceRequest,
	error,
) {
	nodeID =
		strings.TrimSpace(
			nodeID,
		)

	reason =
		strings.TrimSpace(
			reason,
		)

	if nodeID == "" ||
		generation < 1 ||
		reason == "" {

		return model.ExecutionFenceRequest{},
			ErrExecutionFenceNotRequestable
	}

	var execution model.ExecutionAssignment

	err :=
		p.Pool.QueryRow(
			ctx,
			`
			SELECT
				id::text,
				generation,
				execution_id::text,
				execution_epoch
			FROM deployments
			WHERE node_id = $1::uuid
			  AND generation = $2::bigint
			`,
			nodeID,
			generation,
		).Scan(
			&execution.DeploymentID,
			&execution.Generation,
			&execution.ExecutionID,
			&execution.ExecutionEpoch,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.ExecutionFenceRequest{},
			ErrNotFound
	}

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	// Execution identity is immutable. The inner method
	// re-locks and re-validates deployment/node/lease state
	// transactionally before the request can be created.
	return p.CreateExecutionFenceRequest(
		ctx,
		nodeID,
		execution,
		reason,
	)
}
