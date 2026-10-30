package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

const (
	leaseSupervisorInterval = 5 * time.Second

	leaseTransientRetryAfter = 5 * time.Second

	leaseRequestMaxTimeout = 10 * time.Second
)

type leasedExecution struct {
	Assignment model.AgentAssignment

	OwnerInstanceID string

	// LeaseToken is the live execution authority credential.
	// It is deliberately RAM-only and must be cleared as soon
	// as execution authority is lost.
	LeaseToken string

	// FenceProofToken is the original RAM-only lease proof.
	// Losing execution authority MUST NOT clear this value:
	// it is retained solely so the same process instance can
	// later prove physical quiescence to the fencing protocol.
	//
	// Never persist, log, audit, or expose this token.
	FenceProofToken string

	LeaseExpiresAt time.Time
	NextRenewAt    time.Time
	RenewAfter     time.Duration

	ApplyingAccepted bool
	LeaseLost        bool

	// FenceRequest is an already-observed physical fencing
	// request for this exact execution. It is RAM-only so an
	// ACK can be retried even if a previous ACK committed but
	// its HTTP response was lost and assignment later stops
	// exposing the acknowledged request.
	FenceRequest *model.ExecutionFenceRequest

	Worker *deploymentWorker

	PendingResult *deploymentWorkerResult
}

type terminalHealthDriver interface {
	Health() (
		bool,
		error,
	)

	CurrentVersion() string
}

type leaseRuntimeDriver interface {
	deploymentReconciler
	terminalHealthDriver
}

func validateLeaseAssignment(
	assignment model.AgentAssignment,
) error {
	if err :=
		validateAssignment(
			assignment,
		); err != nil {

		return err
	}

	if assignment.NodeAppliedGeneration < 0 {
		return fmt.Errorf(
			"assignment node applied generation must be >= 0",
		)
	}

	if fence := assignment.FenceRequest; fence != nil {
		if fence.ID == "" {
			return fmt.Errorf(
				"assignment fence request id missing",
			)
		}

		if fence.State != "requested" {
			return fmt.Errorf(
				"assignment fence state=%q want=requested",
				fence.State,
			)
		}

		if fence.DeploymentID !=
			assignment.Execution.DeploymentID ||
			fence.Generation !=
				assignment.Execution.Generation ||
			fence.ExecutionID !=
				assignment.Execution.ExecutionID ||
			fence.ExecutionEpoch !=
				assignment.Execution.ExecutionEpoch {

			return fmt.Errorf(
				"assignment fence execution identity mismatch",
			)
		}

		if fence.TargetOwnerInstanceID == "" {
			return fmt.Errorf(
				"assignment fence target owner missing",
			)
		}

		if assignment.DeploymentStatus != "pending" &&
			assignment.DeploymentStatus != "applying" {

			return fmt.Errorf(
				"assignment fence attached to terminal deployment status %q",
				assignment.DeploymentStatus,
			)
		}
	}

	switch assignment.DeploymentStatus {
	case "pending",
		"applying":

		if assignment.NodeAppliedGeneration >=
			assignment.DesiredState.Generation {

			return fmt.Errorf(
				"non-terminal assignment generation=%d has authoritative applied generation=%d",
				assignment.DesiredState.Generation,
				assignment.NodeAppliedGeneration,
			)
		}

	case "healthy":

		if assignment.NodeAppliedGeneration <
			assignment.DesiredState.Generation {

			return fmt.Errorf(
				"healthy assignment generation=%d has authoritative applied generation=%d",
				assignment.DesiredState.Generation,
				assignment.NodeAppliedGeneration,
			)
		}

	case "failed",
		"rolled_back":

		if assignment.NodeAppliedGeneration >=
			assignment.DesiredState.Generation {

			return fmt.Errorf(
				"failed assignment generation=%d has invalid authoritative applied generation=%d",
				assignment.DesiredState.Generation,
				assignment.NodeAppliedGeneration,
			)
		}

	default:
		return fmt.Errorf(
			"invalid assignment deployment status %q",
			assignment.DeploymentStatus,
		)
	}

	return nil
}

func terminalAssignment(
	assignment model.AgentAssignment,
) bool {
	switch assignment.DeploymentStatus {
	case "healthy",
		"failed",
		"rolled_back":
		return true

	default:
		return false
	}
}

func nonRetryableLeaseHTTPError(
	err error,
) bool {
	status, ok :=
		agent.HTTPErrorStatus(
			err,
		)

	if !ok {
		return false
	}

	if status < 400 ||
		status >= 500 {

		return false
	}

	switch status {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests:

		return false

	default:
		return true
	}
}

func leaseRequestTimeout(
	expiresAt time.Time,
) (
	time.Duration,
	bool,
) {
	remaining :=
		time.Until(
			expiresAt,
		)

	if remaining <= 0 {
		return 0,
			false
	}

	if remaining >
		leaseRequestMaxTimeout {

		remaining =
			leaseRequestMaxTimeout
	}

	return remaining,
		true
}

func newLeasedExecution(
	assignment model.AgentAssignment,
	ownerInstanceID string,
	grant model.ExecutionLeaseGrant,
) (
	*leasedExecution,
	error,
) {
	now :=
		time.Now().UTC()

	if !grant.LeaseExpiresAt.After(
		now,
	) {
		return nil,
			fmt.Errorf(
				"execution lease already expired",
			)
	}

	if grant.RenewAfterSeconds < 1 {
		return nil,
			fmt.Errorf(
				"execution lease invalid renew interval",
			)
	}

	renewAfter :=
		time.Duration(
			grant.RenewAfterSeconds,
		) * time.Second

	return &leasedExecution{
			Assignment: assignment,

			OwnerInstanceID: ownerInstanceID,

			LeaseToken: grant.LeaseToken,

			FenceProofToken: grant.LeaseToken,

			LeaseExpiresAt: grant.LeaseExpiresAt,

			NextRenewAt: now.Add(
				renewAfter,
			),

			RenewAfter: renewAfter,
		},
		nil
}

func clearLeaseAuthority(
	execution *leasedExecution,
) {
	if execution == nil {
		return
	}

	execution.LeaseToken = ""
}

func clearLeaseSecrets(
	execution *leasedExecution,
) {
	if execution == nil {
		return
	}

	execution.LeaseToken = ""
	execution.FenceProofToken = ""
}

func markLeaseLost(
	execution *leasedExecution,
	reason string,
) {
	if execution == nil ||
		execution.LeaseLost {

		return
	}

	execution.LeaseLost =
		true

	clearLeaseAuthority(
		execution,
	)

	if execution.Worker != nil {
		execution.Worker.cancel()
	}

	log.Printf(
		"execution lease authority lost generation=%d execution=%s epoch=%d reason=%s; worker cancellation requested",
		execution.Assignment.Execution.Generation,
		execution.Assignment.Execution.ExecutionID,
		execution.Assignment.Execution.ExecutionEpoch,
		reason,
	)
}

func sameExecutionFenceRequest(
	left *model.ExecutionFenceRequest,
	right *model.ExecutionFenceRequest,
) bool {
	if left == nil ||
		right == nil {

		return left == right
	}

	return left.ID ==
		right.ID &&
		left.DeploymentID ==
			right.DeploymentID &&
		left.Generation ==
			right.Generation &&
		left.ExecutionID ==
			right.ExecutionID &&
		left.ExecutionEpoch ==
			right.ExecutionEpoch &&
		left.TargetOwnerInstanceID ==
			right.TargetOwnerInstanceID
}

func observeExecutionFence(
	execution *leasedExecution,
	request *model.ExecutionFenceRequest,
) error {
	if execution == nil {
		return fmt.Errorf(
			"cannot observe execution fence without leased execution",
		)
	}

	if request == nil {
		return nil
	}

	if request.ID == "" ||
		request.State != "requested" {

		return fmt.Errorf(
			"invalid requested execution fence",
		)
	}

	identity :=
		execution.Assignment.Execution

	if request.DeploymentID !=
		identity.DeploymentID ||
		request.Generation !=
			identity.Generation ||
		request.ExecutionID !=
			identity.ExecutionID ||
		request.ExecutionEpoch !=
			identity.ExecutionEpoch {

		return fmt.Errorf(
			"execution fence identity mismatch",
		)
	}

	if request.TargetOwnerInstanceID !=
		execution.OwnerInstanceID {

		return fmt.Errorf(
			"execution fence targets a different process owner",
		)
	}

	if execution.FenceRequest != nil {
		if !sameExecutionFenceRequest(
			execution.FenceRequest,
			request,
		) {
			return fmt.Errorf(
				"conflicting execution fence request observed",
			)
		}

		// Same request was already retained in RAM.
		// Still make sure authority is revoked.
		markLeaseLost(
			execution,
			"execution fence requested",
		)

		return nil
	}

	copyRequest :=
		*request

	execution.FenceRequest =
		&copyRequest

	// Observation of a valid exact fence request revokes all
	// execution authority immediately. markLeaseLost clears
	// LeaseToken but deliberately preserves FenceProofToken.
	markLeaseLost(
		execution,
		"execution fence requested",
	)

	return nil
}

func acknowledgeObservedExecutionFence(
	ctx context.Context,
	client *agent.Client,
	localState *agent.LocalState,
	execution *leasedExecution,
) (
	bool,
	error,
) {
	if execution == nil ||
		execution.FenceRequest == nil {

		return false,
			nil
	}

	// A non-nil Worker means physical quiescence has NOT yet
	// been observed by the supervisor. cancel() being called
	// is insufficient proof.
	if execution.Worker != nil {
		return false,
			nil
	}

	if !execution.LeaseLost {
		return false,
			fmt.Errorf(
				"execution fence cannot be acknowledged while lease authority is still active",
			)
	}

	if execution.FenceProofToken == "" {
		return false,
			fmt.Errorf(
				"execution fence proof unavailable in this process",
			)
	}

	request :=
		execution.FenceRequest

	ackCtx, cancel :=
		context.WithTimeout(
			ctx,
			leaseRequestMaxTimeout,
		)

	defer cancel()

	acknowledged, err :=
		client.AcknowledgeExecutionFence(
			ackCtx,
			localState.AgentToken,
			model.ExecutionFenceAckRequest{
				FenceRequestID: request.ID,

				Execution: execution.Assignment.Execution,

				OwnerInstanceID: execution.OwnerInstanceID,

				FenceProofToken: execution.FenceProofToken,
			},
		)

	if err != nil {
		// Keep FenceRequest + FenceProofToken in RAM.
		// A lost HTTP response after a committed ACK is safe:
		// the next retry is idempotent at Control Plane.
		return false,
			err
	}

	if acknowledged.ID !=
		request.ID {

		return false,
			fmt.Errorf(
				"execution fence acknowledgement request id mismatch",
			)
	}

	if acknowledged.State !=
		"acknowledged" {

		return false,
			fmt.Errorf(
				"execution fence acknowledgement state=%q",
				acknowledged.State,
			)
	}

	// Control Plane has now transactionally committed:
	// request=acknowledged + lease=fenced.
	// The raw proof has served its only purpose.
	clearLeaseSecrets(
		execution,
	)

	return true,
		nil
}

func sendLeasedDeploymentStatus(
	ctx context.Context,
	client *agent.Client,
	localState *agent.LocalState,
	execution *leasedExecution,
	status string,
	appliedCoreVersion string,
	errorMessage string,
) error {
	if execution == nil {
		return fmt.Errorf(
			"leased execution missing",
		)
	}

	if execution.LeaseToken == "" {
		return fmt.Errorf(
			"execution lease token unavailable",
		)
	}

	identity :=
		execution.Assignment.Execution

	return client.DeploymentStatus(
		ctx,
		localState.AgentToken,
		model.DeploymentReport{
			Generation: identity.Generation,

			DeploymentID: identity.DeploymentID,

			ExecutionID: identity.ExecutionID,

			ExecutionEpoch: identity.ExecutionEpoch,

			OwnerInstanceID: execution.OwnerInstanceID,

			LeaseToken: execution.LeaseToken,

			Status: status,

			AppliedCoreVersion: appliedCoreVersion,

			ErrorMessage: errorMessage,

			ReportedAt: time.Now().UTC(),
		},
	)
}

func recoverTerminalAssignment(
	driver terminalHealthDriver,
	statePath string,
	localState *agent.LocalState,
	assignment model.AgentAssignment,
) (bool, error) {
	return recoverTerminalAssignmentContext(context.Background(), driver, statePath, localState, assignment)
}

func recoverTerminalAssignmentContext(
	parent context.Context,
	driver terminalHealthDriver,
	statePath string,
	localState *agent.LocalState,
	assignment model.AgentAssignment,
) (
	bool,
	error,
) {
	if restorer, ok := driver.(interface {
		RestoreTerminalAssignment(context.Context, model.AgentAssignment) error
	}); ok {
		ctx, cancel := context.WithTimeout(parent, 20*time.Second)
		err := restorer.RestoreTerminalAssignment(ctx, assignment)
		cancel()
		if err != nil {
			return false, err
		}
	}
	switch assignment.DeploymentStatus {
	case "healthy":
		healthy, err :=
			driver.Health()

		if err != nil {
			return false,
				fmt.Errorf(
					"cannot repair healthy terminal assignment: %w",
					err,
				)
		}

		if !healthy {
			return false,
				fmt.Errorf(
					"cannot repair healthy terminal assignment: local core is unhealthy",
				)
		}

		if assignment.AppliedCoreVersion != "" &&
			driver.CurrentVersion() !=
				assignment.AppliedCoreVersion {

			return false,
				fmt.Errorf(
					"cannot repair terminal assignment: local core version=%q authoritative=%q",
					driver.CurrentVersion(),
					assignment.AppliedCoreVersion,
				)
		}

		changed :=
			localState.AppliedGeneration !=
				assignment.NodeAppliedGeneration ||
				localState.FailedGeneration !=
					0 ||
				localState.FailureCount !=
					0 ||
				localState.NextRetryUnix !=
					0

		localState.AppliedGeneration =
			assignment.NodeAppliedGeneration

		localState.FailedGeneration = 0
		localState.FailureCount = 0
		localState.NextRetryUnix = 0

		if changed {
			if err :=
				agent.SaveState(
					statePath,
					*localState,
				); err != nil {

				return false,
					err
			}
		}

		return true,
			nil

	case "failed",
		"rolled_back":

		changed :=
			localState.AppliedGeneration !=
				assignment.NodeAppliedGeneration ||
				localState.FailedGeneration !=
					assignment.DesiredState.Generation ||
				localState.FailureCount !=
					0 ||
				localState.NextRetryUnix !=
					0

		localState.AppliedGeneration =
			assignment.NodeAppliedGeneration

		localState.FailedGeneration =
			assignment.DesiredState.Generation

		localState.FailureCount = 0
		localState.NextRetryUnix = 0

		if changed {
			if err :=
				agent.SaveState(
					statePath,
					*localState,
				); err != nil {

				return false,
					err
			}
		}

		return true,
			nil

	default:
		return false,
			nil
	}
}

func claimLeasedExecution(
	ctx context.Context,
	client *agent.Client,
	localState *agent.LocalState,
	assignment model.AgentAssignment,
	ownerInstanceID string,
) (
	*leasedExecution,
	error,
) {
	grant, err :=
		client.ClaimExecutionLease(
			ctx,
			localState.AgentToken,
			model.ExecutionLeaseClaimRequest{
				Execution: assignment.Execution,

				OwnerInstanceID: ownerInstanceID,
			},
		)

	if err != nil {
		return nil,
			err
	}

	return newLeasedExecution(
		assignment,
		ownerInstanceID,
		grant,
	)
}

func renewLeasedExecution(
	ctx context.Context,
	client *agent.Client,
	localState *agent.LocalState,
	execution *leasedExecution,
) (
	bool,
	error,
) {
	if execution == nil ||
		execution.LeaseLost {

		return false,
			nil
	}

	now :=
		time.Now().UTC()

	if !execution.LeaseExpiresAt.After(
		now,
	) {
		markLeaseLost(
			execution,
			"local lease expiry reached",
		)

		return true,
			nil
	}

	if now.Before(
		execution.NextRenewAt,
	) {
		return false,
			nil
	}

	timeout, valid :=
		leaseRequestTimeout(
			execution.LeaseExpiresAt,
		)

	if !valid {
		markLeaseLost(
			execution,
			"local lease expiry reached before renewal",
		)

		return true,
			nil
	}

	renewCtx, cancel :=
		context.WithTimeout(
			ctx,
			timeout,
		)

	defer cancel()

	grant, err :=
		client.RenewExecutionLease(
			renewCtx,
			localState.AgentToken,
			model.ExecutionLeaseRenewRequest{
				Execution: execution.Assignment.Execution,

				OwnerInstanceID: execution.OwnerInstanceID,

				LeaseToken: execution.LeaseToken,
			},
		)

	if err != nil {
		if nonRetryableLeaseHTTPError(
			err,
		) {
			markLeaseLost(
				execution,
				"control plane rejected lease renewal",
			)

			return true,
				err
		}

		now =
			time.Now().UTC()

		if !execution.LeaseExpiresAt.After(
			now,
		) {
			markLeaseLost(
				execution,
				"lease expired after renewal failure",
			)

			return true,
				err
		}

		execution.NextRenewAt =
			now.Add(
				leaseTransientRetryAfter,
			)

		if execution.NextRenewAt.After(
			execution.LeaseExpiresAt,
		) {
			execution.NextRenewAt =
				execution.LeaseExpiresAt
		}

		return false,
			err
	}

	now =
		time.Now().UTC()

	if !grant.LeaseExpiresAt.After(
		now,
	) {
		markLeaseLost(
			execution,
			"control plane returned expired lease",
		)

		return true,
			fmt.Errorf(
				"renewed execution lease is not in the future",
			)
	}

	if grant.RenewAfterSeconds < 1 {
		markLeaseLost(
			execution,
			"control plane returned invalid renewal interval",
		)

		return true,
			fmt.Errorf(
				"renewed execution lease has invalid renew interval",
			)
	}

	execution.LeaseExpiresAt =
		grant.LeaseExpiresAt

	execution.RenewAfter =
		time.Duration(
			grant.RenewAfterSeconds,
		) * time.Second

	execution.NextRenewAt =
		now.Add(
			execution.RenewAfter,
		)

	return false,
		nil
}

type realityPublicMaterialProvider interface {
	RealityPublicMaterials(
		state model.DesiredState,
	) ([]model.RealityPublicMaterial, error)
}

func syncRealityPublicMaterials(
	ctx context.Context,
	client *agent.Client,
	driver leaseRuntimeDriver,
	agentToken string,
	state model.DesiredState,
) error {
	provider, ok :=
		driver.(realityPublicMaterialProvider)

	if !ok {
		return nil
	}

	materials, err :=
		provider.RealityPublicMaterials(
			state,
		)

	if err != nil {
		return err
	}

	for _, material := range materials {

		if err :=
			client.RealityMaterial(
				ctx,
				agentToken,
				material,
			); err != nil {

			return err
		}
	}

	return nil
}

func commitTerminalWorkerResult(
	ctx context.Context,
	client *agent.Client,
	driver leaseRuntimeDriver,
	statePath string,
	localState *agent.LocalState,
	execution *leasedExecution,
) (
	bool,
	bool,
	error,
) {
	if execution == nil ||
		execution.PendingResult == nil {

		return false,
			false,
			nil
	}

	result :=
		*execution.PendingResult

	status :=
		"healthy"

	appliedCoreVersion :=
		driver.CurrentVersion()

	errorMessage :=
		""

	if result.Err == nil {
		if err :=
			syncRealityPublicMaterials(
				ctx,
				client,
				driver,
				localState.AgentToken,
				execution.Assignment.DesiredState,
			); err != nil {

			return false,
				false,
				fmt.Errorf(
					"sync reality public material: %w",
					err,
				)
		}
	}

	if result.Err != nil {
		healthy, _ :=
			driver.Health()

		status =
			"failed"

		appliedCoreVersion =
			""

		if healthy {
			status =
				"rolled_back"

			appliedCoreVersion =
				driver.CurrentVersion()
		}

		errorMessage =
			result.Err.Error()
	}

	err :=
		sendLeasedDeploymentStatus(
			ctx,
			client,
			localState,
			execution,
			status,
			appliedCoreVersion,
			errorMessage,
		)

	if err != nil {
		if nonRetryableLeaseHTTPError(
			err,
		) {
			markLeaseLost(
				execution,
				"terminal report rejected by control plane",
			)

			return false,
				true,
				err
		}

		return false,
			false,
			err
	}

	// Only now, after Control Plane atomically committed the
	// terminal deployment + completed lease, may LocalState
	// advance its checkpoint.
	if result.Err == nil {
		if confirmer, ok := driver.(interface {
			ConfirmHealthyDesired(context.Context, model.DesiredState) error
		}); ok {
			if err := confirmer.ConfirmHealthyDesired(ctx, execution.Assignment.DesiredState); err != nil {
				return true, false, err
			}
		}
	}
	if result.Err == nil {
		localState.AppliedGeneration =
			result.Generation

		localState.FailedGeneration = 0
		localState.FailureCount = 0
		localState.NextRetryUnix = 0

	} else {
		localState.FailedGeneration =
			result.Generation

		localState.FailureCount = 0
		localState.NextRetryUnix = 0
	}

	if err :=
		agent.SaveState(
			statePath,
			*localState,
		); err != nil {

		// The Control Plane transaction already succeeded.
		// On restart / next assignment poll, terminal state
		// recovery repairs this local checkpoint.
		return true,
			false,
			err
	}

	clearLeaseSecrets(
		execution,
	)

	return true,
		false,
		nil
}

func sendLeaseSupervisorHealth(
	ctx context.Context,
	client *agent.Client,
	driver terminalHealthDriver,
	system agent.SystemInfo,
	localState *agent.LocalState,
	healthy bool,
	message string,
) error {
	return client.Health(
		ctx,
		localState.AgentToken,
		model.HealthReport{
			RuntimeRecoveryInfo: runtimeRecoveryInfo(driver),
			Healthy:             healthy,

			AppliedGeneration: localState.AppliedGeneration,

			Core: runtimeCoreType(driver),

			CoreVersion: driver.CurrentVersion(),

			Message: message,

			CheckedAt: time.Now().UTC(),

			AgentVersion: agentVersion,

			OSName: system.OSName,

			OSVersion: system.OSVersion,

			Architecture: system.Architecture,

			Metrics: collectNodeMetrics(),

			TrafficSnapshot: collectClientTraffic(),
		},
	)
}

func advanceLeasedExecution(
	ctx context.Context,
	client *agent.Client,
	driver leaseRuntimeDriver,
	statePath string,
	system agent.SystemInfo,
	localState *agent.LocalState,
	execution **leasedExecution,
) error {
	current :=
		*execution

	if current == nil {
		return nil
	}

	// Once a fence request has been observed, this execution
	// leaves the normal deployment state machine permanently.
	// No pending worker result may be published as a terminal
	// deployment outcome. The only valid path is:
	//
	// cancel -> worker.done -> fence ACK.
	if current.FenceRequest != nil {
		if !current.LeaseLost {
			markLeaseLost(
				current,
				"execution fence requested",
			)
		}

		if current.Worker != nil {
			healthy, _ :=
				driver.Health()

			return sendLeaseSupervisorHealth(
				ctx,
				client,
				driver,
				system,
				localState,
				healthy,
				fmt.Sprintf(
					"generation %d execution epoch %d fencing requested; waiting for physical worker quiescence",
					current.Assignment.Execution.Generation,
					current.Assignment.Execution.ExecutionEpoch,
				),
			)
		}

		acknowledged, err :=
			acknowledgeObservedExecutionFence(
				ctx,
				client,
				localState,
				current,
			)

		if err != nil {
			return err
		}

		if !acknowledged {
			return fmt.Errorf(
				"execution fence acknowledgement not completed",
			)
		}

		*execution = nil

		healthy, healthErr :=
			driver.Health()

		message :=
			"execution fence acknowledged after physical worker quiescence"

		if healthErr != nil {
			healthy = false
			message =
				healthErr.Error()
		}

		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			message,
		)
	}

	if current.LeaseLost {
		healthy, _ :=
			driver.Health()

		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			fmt.Sprintf(
				"generation %d execution epoch %d lease authority lost; awaiting fencing/recovery",
				current.Assignment.Execution.Generation,
				current.Assignment.Execution.ExecutionEpoch,
			),
		)
	}

	_, renewErr :=
		renewLeasedExecution(
			ctx,
			client,
			localState,
			current,
		)

	if current.LeaseLost {
		healthy, _ :=
			driver.Health()

		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			fmt.Sprintf(
				"generation %d execution epoch %d lease authority lost; worker cancellation requested",
				current.Assignment.Execution.Generation,
				current.Assignment.Execution.ExecutionEpoch,
			),
		)
	}

	// A transient renew failure does not immediately kill
	// the worker. Local lease expiry remains the hard limit.
	if renewErr != nil {
		log.Printf(
			"execution lease renew transient error generation=%d execution=%s epoch=%d: %v",
			current.Assignment.Execution.Generation,
			current.Assignment.Execution.ExecutionID,
			current.Assignment.Execution.ExecutionEpoch,
			renewErr,
		)
	}

	if current.PendingResult != nil {
		committed, lost, err :=
			commitTerminalWorkerResult(
				ctx,
				client,
				driver,
				statePath,
				localState,
				current,
			)

		if lost {
			return err
		}

		if committed {
			*execution = nil

			if err != nil {
				return err
			}

			healthy, healthErr :=
				driver.Health()

			message :=
				"healthy"

			if healthErr != nil {
				healthy = false
				message = healthErr.Error()
			}

			return sendLeaseSupervisorHealth(
				ctx,
				client,
				driver,
				system,
				localState,
				healthy,
				message,
			)
		}

		if err != nil {
			return err
		}
	}

	if !current.ApplyingAccepted {
		if current.Assignment.DeploymentStatus ==
			"applying" {

			// Applying may already have committed while the
			// HTTP response was lost. We still hold the exact
			// execution lease, so continuation is safe.
			current.ApplyingAccepted =
				true

		} else {
			err :=
				sendLeasedDeploymentStatus(
					ctx,
					client,
					localState,
					current,
					"applying",
					"",
					"",
				)

			if err != nil {
				if nonRetryableLeaseHTTPError(
					err,
				) {
					markLeaseLost(
						current,
						"applying report rejected by control plane",
					)
				}

				return err
			}

			current.ApplyingAccepted =
				true
		}
	}

	if current.ApplyingAccepted &&
		current.Worker == nil &&
		current.PendingResult == nil {

		log.Printf(
			"starting leased deployment worker generation=%d execution=%s epoch=%d core=%s version=%s",
			current.Assignment.DesiredState.Generation,
			current.Assignment.Execution.ExecutionID,
			current.Assignment.Execution.ExecutionEpoch,
			current.Assignment.DesiredState.Core.Type,
			current.Assignment.DesiredState.Core.Version,
		)

		current.Worker =
			startDeploymentWorker(
				ctx,
				driver,
				current.Assignment,
			)
	}

	healthy, healthErr :=
		driver.Health()

	message :=
		fmt.Sprintf(
			"deployment generation %d execution epoch %d in progress under active execution lease",
			current.Assignment.Execution.Generation,
			current.Assignment.Execution.ExecutionEpoch,
		)

	if healthErr != nil {
		healthy = false

		message =
			fmt.Sprintf(
				"deployment generation %d execution epoch %d in progress; health check: %v",
				current.Assignment.Execution.Generation,
				current.Assignment.Execution.ExecutionEpoch,
				healthErr,
			)
	}

	return sendLeaseSupervisorHealth(
		ctx,
		client,
		driver,
		system,
		localState,
		healthy,
		message,
	)
}

func leaseSupervisorTick(
	ctx context.Context,
	client *agent.Client,
	driver leaseRuntimeDriver,
	statePath string,
	system agent.SystemInfo,
	localState *agent.LocalState,
	ownerInstanceID string,
	execution **leasedExecution,
) error {
	// An already-observed physical fence has absolute priority.
	// Once retained in RAM, fencing must not depend on another
	// assignment poll. This also permits idempotent ACK retry
	// after the Control Plane committed the ACK but the HTTP
	// response was lost.
	if *execution != nil &&
		(*execution).FenceRequest != nil {

		return advanceLeasedExecution(
			ctx,
			client,
			driver,
			statePath,
			system,
			localState,
			execution,
		)
	}

	// Lease authority is serviced BEFORE assignment polling.
	//
	// Assignment is advisory/control-plane state and its endpoint
	// may temporarily fail. A failure there must never prevent:
	//   - lease renewal;
	//   - local lease expiry enforcement;
	//   - worker cancellation after authority expires.
	if *execution != nil &&
		!(*execution).LeaseLost {

		current :=
			*execution

		_, renewErr :=
			renewLeasedExecution(
				ctx,
				client,
				localState,
				current,
			)

		if current.LeaseLost {
			return advanceLeasedExecution(
				ctx,
				client,
				driver,
				statePath,
				system,
				localState,
				execution,
			)
		}

		if renewErr != nil {
			log.Printf(
				"execution lease renew transient error generation=%d execution=%s epoch=%d before assignment poll: %v",
				current.Assignment.Execution.Generation,
				current.Assignment.Execution.ExecutionID,
				current.Assignment.Execution.ExecutionEpoch,
				renewErr,
			)
		}
	}

	assignment, exists, err :=
		client.Assignment(
			ctx,
			localState.AgentToken,
		)

	if err != nil {
		return err
	}

	if exists {
		if err :=
			validateLeaseAssignment(
				assignment,
			); err != nil {

			return err
		}
	}

	if *execution != nil {
		current :=
			*execution

		if !exists {
			markLeaseLost(
				current,
				"assignment disappeared",
			)

			return advanceLeasedExecution(
				ctx,
				client,
				driver,
				statePath,
				system,
				localState,
				execution,
			)
		}

		if !sameExecution(
			current.Assignment.Execution,
			assignment.Execution,
		) {
			markLeaseLost(
				current,
				"assignment execution identity changed",
			)

			return advanceLeasedExecution(
				ctx,
				client,
				driver,
				statePath,
				system,
				localState,
				execution,
			)
		}

		// A requested fence belongs to the exact currently-owned
		// execution. Observe it before entering any normal
		// deployment/terminal path.
		if assignment.FenceRequest != nil {
			if err :=
				observeExecutionFence(
					current,
					assignment.FenceRequest,
				); err != nil {

				// Invalid/conflicting fence information is itself
				// authority uncertainty. Fail closed.
				markLeaseLost(
					current,
					"invalid or conflicting execution fence request",
				)

				return err
			}
		}

		// Keep authoritative assignment fields current.
		current.Assignment =
			assignment

		if current.FenceRequest != nil {
			return advanceLeasedExecution(
				ctx,
				client,
				driver,
				statePath,
				system,
				localState,
				execution,
			)
		}

		if terminalAssignment(
			assignment,
		) {
			// Terminal CP state wins. If a local worker still
			// exists, cancel it and wait for physical quiescence
			// before repairing LocalState.
			if current.Worker != nil {
				markLeaseLost(
					current,
					"control plane reports terminal execution while local worker still exists",
				)

				healthy, _ :=
					driver.Health()

				return sendLeaseSupervisorHealth(
					ctx,
					client,
					driver,
					system,
					localState,
					healthy,
					"terminal execution observed; waiting for local worker quiescence",
				)
			}

			recovered, err :=
				recoverTerminalAssignmentContext(
					ctx,
					driver,
					statePath,
					localState,
					assignment,
				)

			if err != nil {
				return err
			}

			if recovered {
				clearLeaseSecrets(
					current,
				)

				*execution = nil
			}

			healthy, healthErr :=
				driver.Health()

			message :=
				"terminal assignment recovered"

			if healthErr != nil {
				healthy = false
				message = healthErr.Error()
			}

			return sendLeaseSupervisorHealth(
				ctx,
				client,
				driver,
				system,
				localState,
				healthy,
				message,
			)
		}

		return advanceLeasedExecution(
			ctx,
			client,
			driver,
			statePath,
			system,
			localState,
			execution,
		)
	}

	if !exists {
		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			true,
			"agent online; waiting for assignment",
		)
	}

	// A process that did not own this execution has no
	// FenceProofToken in RAM. It must never claim or ACK an
	// execution for which physical fencing is already requested.
	if assignment.FenceRequest != nil {
		healthy, _ :=
			driver.Health()

		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			fmt.Sprintf(
				"generation %d has a requested execution fence but this process owns no RAM fencing proof; awaiting fencing/recovery",
				assignment.DesiredState.Generation,
			),
		)
	}

	if terminalAssignment(
		assignment,
	) {
		recovered, err :=
			recoverTerminalAssignmentContext(
				ctx,
				driver,
				statePath,
				localState,
				assignment,
			)

		if err != nil {
			return err
		}

		if !recovered {
			return fmt.Errorf(
				"terminal assignment could not be recovered",
			)
		}

		healthy, healthErr :=
			driver.Health()

		message :=
			"terminal assignment recovered"

		if healthErr != nil {
			healthy = false
			message = healthErr.Error()
		}

		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			message,
		)
	}

	if assignment.DeploymentStatus ==
		"applying" {

		healthy, _ :=
			driver.Health()

		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			fmt.Sprintf(
				"generation %d is applying but this process owns no execution lease; awaiting fencing/recovery",
				assignment.DesiredState.Generation,
			),
		)
	}

	if assignment.DeploymentStatus !=
		"pending" {

		return fmt.Errorf(
			"unexpected non-terminal deployment status %q",
			assignment.DeploymentStatus,
		)
	}

	if assignment.DesiredState.Generation <=
		localState.AppliedGeneration {

		healthy, _ :=
			driver.Health()

		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			fmt.Sprintf(
				"pending generation %d is not newer than local applied generation %d; refusing execution",
				assignment.DesiredState.Generation,
				localState.AppliedGeneration,
			),
		)
	}

	if generationAwaitingRecovery(
		assignment.DesiredState.Generation,
		localState.AppliedGeneration,
		localState.FailedGeneration,
	) {
		healthy, _ :=
			driver.Health()

		return sendLeaseSupervisorHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			fmt.Sprintf(
				"generation %d is terminal in local state; awaiting recovery decision",
				assignment.DesiredState.Generation,
			),
		)
	}

	claimed, err :=
		claimLeasedExecution(
			ctx,
			client,
			localState,
			assignment,
			ownerInstanceID,
		)

	if err != nil {
		return err
	}

	*execution =
		claimed

	return advanceLeasedExecution(
		ctx,
		client,
		driver,
		statePath,
		system,
		localState,
		execution,
	)
}

func runLeaseSupervisor(
	ctx context.Context,
	client *agent.Client,
	driver leaseRuntimeDriver,
	statePath string,
	system agent.SystemInfo,
	localState *agent.LocalState,
	ownerInstanceID string,
) {
	ticker :=
		time.NewTicker(
			leaseSupervisorInterval,
		)

	defer ticker.Stop()

	var execution *leasedExecution

	for {
		if err :=
			leaseSupervisorTick(
				ctx,
				client,
				driver,
				statePath,
				system,
				localState,
				ownerInstanceID,
				&execution,
			); err != nil {

			if ctx.Err() == nil {
				log.Printf(
					"lease supervisor tick error: %v",
					err,
				)
			}
		}

		var workerDone <-chan deploymentWorkerResult

		if execution != nil &&
			execution.Worker != nil {

			workerDone =
				execution.Worker.done
		}

		select {
		case <-ctx.Done():
			if execution != nil {
				if execution.Worker != nil {
					log.Printf(
						"agent shutdown: cancelling leased deployment worker generation=%d execution=%s epoch=%d",
						execution.Assignment.Execution.Generation,
						execution.Assignment.Execution.ExecutionID,
						execution.Assignment.Execution.ExecutionEpoch,
					)

					_, stopped :=
						waitForWorkerShutdown(
							execution.Worker,
						)

					if !stopped {
						log.Printf(
							"leased deployment worker did not stop within %s",
							workerShutdownTimeout,
						)
					}
				}

				clearLeaseSecrets(
					execution,
				)
			}

			// Intentional shutdown does not forge a deployment
			// failure. Control Plane fencing/recovery will decide
			// the unfinished execution state.
			return

		case result :=
			<-workerDone:

			if execution == nil ||
				execution.Worker == nil {

				continue
			}

			if !sameExecution(
				execution.Assignment.Execution,
				result.Execution,
			) {
				log.Printf(
					"ignoring worker result for unexpected execution=%s epoch=%d",
					result.Execution.ExecutionID,
					result.Execution.ExecutionEpoch,
				)

				continue
			}

			execution.Worker =
				nil

			execution.PendingResult =
				&result

		case <-ticker.C:
		}
	}
}
