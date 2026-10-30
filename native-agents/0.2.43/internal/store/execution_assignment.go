package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
)

func (
	p *Postgres,
) AgentAssignment(
	ctx context.Context,
	nodeID string,
) (
	model.AgentAssignment,
	bool,
	error,
) {
	// Deliver a superseded owner's physical fence before the newest desired state.
	if err := p.fenceSupersededExecution(ctx, nodeID); err != nil {
		return model.AgentAssignment{}, false, err
	}
	var raw []byte
	var generation int64

	var nodeTenantID string

	var deploymentID string
	var executionID string
	var executionEpoch int64

	var deploymentStatus string
	var nodeAppliedGeneration int64
	var appliedCoreVersion string

	var fenceRequestID string
	var fenceTenantID string
	var fenceNodeID string
	var fenceDeploymentID string
	var fenceGeneration int64
	var fenceExecutionID string
	var fenceExecutionEpoch int64
	var fenceState string
	var fenceTargetOwnerInstanceID string
	var fenceReason string
	var fenceRequestedAt time.Time
	var fenceCreatedAt time.Time
	var fenceUpdatedAt time.Time

	err :=
		p.Pool.QueryRow(
			ctx,
			`
			SELECT
				ds.document,
				ds.generation,

				n.tenant_id::text,

				COALESCE(
					d.id::text,
					''
				),

				COALESCE(
					d.execution_id::text,
					''
				),

				COALESCE(
					d.execution_epoch,
					0
				),

				COALESCE(
					d.status,
					''
				),

				n.applied_generation,

				COALESCE(
					d.applied_core_version,
					''
				),

				COALESCE(
					f.id::text,
					''
				),

				COALESCE(
					f.tenant_id::text,
					''
				),

				COALESCE(
					f.node_id::text,
					''
				),

				COALESCE(
					f.deployment_id::text,
					''
				),

				COALESCE(
					f.generation,
					0
				),

				COALESCE(
					f.execution_id::text,
					''
				),

				COALESCE(
					f.execution_epoch,
					0
				),

				COALESCE(
					f.state,
					''
				),

				COALESCE(
					f.target_owner_instance_id::text,
					''
				),

				COALESCE(
					f.reason,
					''
				),

				COALESCE(
					f.requested_at,
					'epoch'::timestamptz
				),

				COALESCE(
					f.created_at,
					'epoch'::timestamptz
				),

				COALESCE(
					f.updated_at,
					'epoch'::timestamptz
				)

			FROM desired_states ds

			JOIN nodes n
				ON n.id = ds.node_id

			LEFT JOIN deployments d
				ON d.node_id = ds.node_id
			   AND d.generation = ds.generation

			LEFT JOIN execution_fence_requests f
				ON f.deployment_id = d.id
			   AND f.state = 'requested'

			WHERE ds.node_id = $1::uuid AND n.status<>'retired'

			ORDER BY (f.id IS NOT NULL) DESC, ds.generation DESC

			LIMIT 1
			`,
			nodeID,
		).Scan(
			&raw,
			&generation,
			&nodeTenantID,
			&deploymentID,
			&executionID,
			&executionEpoch,
			&deploymentStatus,
			&nodeAppliedGeneration,
			&appliedCoreVersion,
			&fenceRequestID,
			&fenceTenantID,
			&fenceNodeID,
			&fenceDeploymentID,
			&fenceGeneration,
			&fenceExecutionID,
			&fenceExecutionEpoch,
			&fenceState,
			&fenceTargetOwnerInstanceID,
			&fenceReason,
			&fenceRequestedAt,
			&fenceCreatedAt,
			&fenceUpdatedAt,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.AgentAssignment{},
			false,
			nil
	}

	if err != nil {
		return model.AgentAssignment{},
			false,
			err
	}

	if deploymentID == "" ||
		executionID == "" ||
		executionEpoch < 1 {

		return model.AgentAssignment{},
			false,
			fmt.Errorf(
				"desired generation %d has no valid deployment execution identity",
				generation,
			)
	}

	switch deploymentStatus {
	case "pending",
		"applying",
		"healthy",
		"failed",
		"rolled_back":

	default:
		return model.AgentAssignment{},
			false,
			fmt.Errorf(
				"desired generation %d has invalid deployment status %q",
				generation,
				deploymentStatus,
			)
	}

	var state model.DesiredState

	if err :=
		json.Unmarshal(
			raw,
			&state,
		); err != nil {

		return model.AgentAssignment{},
			false,
			err
	}

	if state.Generation != generation {
		return model.AgentAssignment{},
			false,
			fmt.Errorf(
				"desired state generation mismatch document=%d row=%d",
				state.Generation,
				generation,
			)
	}

	var fenceRequest *model.ExecutionFenceRequest

	if fenceRequestID != "" {
		if fenceState != "requested" ||
			fenceTenantID != nodeTenantID ||
			fenceNodeID != nodeID ||
			fenceDeploymentID != deploymentID ||
			fenceGeneration != generation ||
			fenceExecutionID != executionID ||
			fenceExecutionEpoch != executionEpoch ||
			fenceTargetOwnerInstanceID == "" {

			return model.AgentAssignment{},
				false,
				fmt.Errorf(
					"requested execution fence identity mismatch for generation %d",
					generation,
				)
		}

		if deploymentStatus != "pending" &&
			deploymentStatus != "applying" {

			return model.AgentAssignment{},
				false,
				fmt.Errorf(
					"requested execution fence exists for terminal deployment status %q",
					deploymentStatus,
				)
		}

		fenceRequest =
			&model.ExecutionFenceRequest{
				ID: fenceRequestID,

				TenantID: fenceTenantID,

				NodeID: fenceNodeID,

				DeploymentID: fenceDeploymentID,

				Generation: fenceGeneration,

				ExecutionID: fenceExecutionID,

				ExecutionEpoch: fenceExecutionEpoch,

				State: fenceState,

				TargetOwnerInstanceID: fenceTargetOwnerInstanceID,

				Reason: fenceReason,

				RequestedAt: fenceRequestedAt,

				CreatedAt: fenceCreatedAt,

				UpdatedAt: fenceUpdatedAt,
			}
	}

	if fenceRequest == nil {
		if err := p.validateXrayProfileAssignment(ctx, nodeID, state); err != nil {
			return model.AgentAssignment{}, false, err
		}
	}
	return model.AgentAssignment{
			DesiredState: state,

			Execution: model.ExecutionAssignment{
				DeploymentID: deploymentID,

				Generation: generation,

				ExecutionID: executionID,

				ExecutionEpoch: executionEpoch,
			},

			DeploymentStatus: deploymentStatus,

			NodeAppliedGeneration: nodeAppliedGeneration,

			AppliedCoreVersion: appliedCoreVersion,

			FenceRequest: fenceRequest,
		},
		true,
		nil
}
