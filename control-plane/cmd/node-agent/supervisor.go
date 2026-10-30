package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"vpn-platform/internal/agent"
	"vpn-platform/internal/core/xray"
	"vpn-platform/internal/model"
)

const (
	supervisorInterval = 10 * time.Second

	workerShutdownTimeout = 60 * time.Second
)

type deploymentReconciler interface {
	Reconcile(
		context.Context,
		model.DesiredState,
	) error
}

type deploymentWorkerResult struct {
	Generation int64

	Execution model.ExecutionAssignment

	Err error
}

type deploymentWorker struct {
	Generation int64

	Execution model.ExecutionAssignment

	cancel context.CancelFunc

	done <-chan deploymentWorkerResult
}

func validateAssignment(
	assignment model.AgentAssignment,
) error {
	if assignment.DesiredState.Generation <
		1 {

		return fmt.Errorf(
			"assignment desired generation must be >= 1",
		)
	}

	if assignment.Execution.Generation !=
		assignment.DesiredState.Generation {

		return fmt.Errorf(
			"assignment generation mismatch desired=%d execution=%d",
			assignment.DesiredState.Generation,
			assignment.Execution.Generation,
		)
	}

	if assignment.Execution.DeploymentID ==
		"" {

		return fmt.Errorf(
			"assignment deployment_id missing",
		)
	}

	if assignment.Execution.ExecutionID ==
		"" {

		return fmt.Errorf(
			"assignment execution_id missing",
		)
	}

	if assignment.Execution.ExecutionEpoch <
		1 {

		return fmt.Errorf(
			"assignment execution_epoch must be >= 1",
		)
	}

	return nil
}

func sameExecution(
	left model.ExecutionAssignment,
	right model.ExecutionAssignment,
) bool {
	return left.DeploymentID ==
		right.DeploymentID &&
		left.Generation ==
			right.Generation &&
		left.ExecutionID ==
			right.ExecutionID &&
		left.ExecutionEpoch ==
			right.ExecutionEpoch
}

func startDeploymentWorker(
	parent context.Context,
	driver deploymentReconciler,
	assignment model.AgentAssignment,
) *deploymentWorker {
	workerCtx, cancel :=
		context.WithCancel(parent)

	done :=
		make(
			chan deploymentWorkerResult,
			1,
		)

	go func() {
		err :=
			driver.Reconcile(
				workerCtx,
				assignment.DesiredState,
			)

		done <- deploymentWorkerResult{
			Generation: assignment.
				DesiredState.
				Generation,

			Execution: assignment.Execution,

			Err: err,
		}

		close(done)
	}()

	return &deploymentWorker{
		Generation: assignment.
			DesiredState.
			Generation,

		Execution: assignment.Execution,

		cancel: cancel,

		done: done,
	}
}

func sendExecutionDeploymentStatus(
	ctx context.Context,
	client *agent.Client,
	localState *agent.LocalState,
	execution model.ExecutionAssignment,
	status string,
	appliedCoreVersion string,
	errorMessage string,
) error {
	return client.DeploymentStatus(
		ctx,
		localState.AgentToken,
		model.DeploymentReport{
			Generation: execution.Generation,

			DeploymentID: execution.DeploymentID,

			ExecutionID: execution.ExecutionID,

			ExecutionEpoch: execution.ExecutionEpoch,

			Status: status,

			AppliedCoreVersion: appliedCoreVersion,

			ErrorMessage: errorMessage,

			ReportedAt: time.Now().UTC(),
		},
	)
}

func supervisorTick(
	ctx context.Context,
	client *agent.Client,
	driver *xray.Driver,
	statePath string,
	system agent.SystemInfo,
	localState *agent.LocalState,
	worker **deploymentWorker,
) error {
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
			validateAssignment(
				assignment,
			); err != nil {

			return err
		}
	}

	if *worker != nil {
		if !exists {
			log.Printf(
				"deployment worker generation=%d active but assignment disappeared; waiting for execution fencing protocol",
				(*worker).Generation,
			)

		} else if !sameExecution(
			(*worker).Execution,
			assignment.Execution,
		) {
			log.Printf(
				"deployment worker generation=%d execution=%s epoch=%d no longer matches assignment execution=%s epoch=%d; waiting for execution fencing protocol",
				(*worker).Generation,
				(*worker).Execution.ExecutionID,
				(*worker).Execution.ExecutionEpoch,
				assignment.Execution.ExecutionID,
				assignment.Execution.ExecutionEpoch,
			)
		}

		healthy, healthErr :=
			driver.Health()

		message :=
			fmt.Sprintf(
				"deployment generation %d execution epoch %d in progress",
				(*worker).Generation,
				(*worker).Execution.ExecutionEpoch,
			)

		if healthErr != nil {
			healthy = false

			message =
				fmt.Sprintf(
					"deployment generation %d execution epoch %d in progress; health check: %v",
					(*worker).Generation,
					(*worker).Execution.ExecutionEpoch,
					healthErr,
				)
		}

		return sendHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			message,
		)
	}

	if !exists {
		return sendHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			true,
			"agent online; waiting for assignment",
		)
	}

	desired :=
		assignment.DesiredState

	execution :=
		assignment.Execution

	if desired.Generation >
		localState.AppliedGeneration {

		if generationAwaitingRecovery(
			desired.Generation,
			localState.AppliedGeneration,
			localState.FailedGeneration,
		) {
			healthy, _ :=
				driver.Health()

			return sendHealth(
				ctx,
				client,
				driver,
				system,
				localState,
				healthy,
				fmt.Sprintf(
					"generation %d terminal after failed deployment; awaiting recovery decision",
					desired.Generation,
				),
			)
		}

		log.Printf(
			"starting deployment worker generation=%d execution=%s epoch=%d core=%s version=%s",
			desired.Generation,
			execution.ExecutionID,
			execution.ExecutionEpoch,
			desired.Core.Type,
			desired.Core.Version,
		)

		if statusErr :=
			sendExecutionDeploymentStatus(
				ctx,
				client,
				localState,
				execution,
				"applying",
				"",
				"",
			); statusErr != nil {

			log.Printf(
				"deployment applying status error: %v",
				statusErr,
			)

			return statusErr
		}

		*worker =
			startDeploymentWorker(
				ctx,
				driver,
				assignment,
			)

		return nil
	}

	healthy, healthErr :=
		driver.Health()

	message :=
		"healthy"

	if healthErr != nil {
		healthy = false
		message = healthErr.Error()
	}

	return sendHealth(
		ctx,
		client,
		driver,
		system,
		localState,
		healthy,
		message,
	)
}

func handleDeploymentWorkerResult(
	ctx context.Context,
	client *agent.Client,
	driver *xray.Driver,
	statePath string,
	system agent.SystemInfo,
	localState *agent.LocalState,
	result deploymentWorkerResult,
) error {
	if result.Err != nil {
		localState.FailedGeneration =
			result.Generation

		localState.FailureCount = 0
		localState.NextRetryUnix = 0

		if err :=
			agent.SaveState(
				statePath,
				*localState,
			); err != nil {

			return err
		}

		healthy, _ :=
			driver.Health()

		deploymentStatus :=
			"failed"

		appliedCoreVersion :=
			""

		if healthy {
			deploymentStatus =
				"rolled_back"

			appliedCoreVersion =
				driver.CurrentVersion()
		}

		message :=
			fmt.Sprintf(
				"generation %d execution epoch %d failed: %v; terminal deployment; awaiting recovery decision",
				result.Generation,
				result.Execution.ExecutionEpoch,
				result.Err,
			)

		if statusErr :=
			sendExecutionDeploymentStatus(
				ctx,
				client,
				localState,
				result.Execution,
				deploymentStatus,
				appliedCoreVersion,
				result.Err.Error(),
			); statusErr != nil {

			log.Printf(
				"deployment failure status error: %v",
				statusErr,
			)
		}

		_ = sendHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			healthy,
			message,
		)

		return fmt.Errorf(
			"%s",
			message,
		)
	}

	localState.AppliedGeneration =
		result.Generation

	localState.FailedGeneration = 0
	localState.FailureCount = 0
	localState.NextRetryUnix = 0

	if err :=
		agent.SaveState(
			statePath,
			*localState,
		); err != nil {

		return err
	}

	log.Printf(
		"generation=%d execution=%s epoch=%d applied successfully",
		result.Generation,
		result.Execution.ExecutionID,
		result.Execution.ExecutionEpoch,
	)

	if statusErr :=
		sendExecutionDeploymentStatus(
			ctx,
			client,
			localState,
			result.Execution,
			"healthy",
			driver.CurrentVersion(),
			"",
		); statusErr != nil {

		log.Printf(
			"deployment healthy status error: %v",
			statusErr,
		)
	}

	healthy, healthErr :=
		driver.Health()

	message :=
		"healthy"

	if healthErr != nil {
		healthy = false
		message = healthErr.Error()
	}

	return sendHealth(
		ctx,
		client,
		driver,
		system,
		localState,
		healthy,
		message,
	)
}

func waitForWorkerShutdown(
	worker *deploymentWorker,
) (
	deploymentWorkerResult,
	bool,
) {
	if worker == nil {
		return deploymentWorkerResult{},
			false
	}

	worker.cancel()

	timer :=
		time.NewTimer(
			workerShutdownTimeout,
		)

	defer timer.Stop()

	select {
	case result :=
		<-worker.done:

		return result,
			true

	case <-timer.C:
		return deploymentWorkerResult{},
			false
	}
}

func runSupervisor(
	ctx context.Context,
	client *agent.Client,
	driver *xray.Driver,
	statePath string,
	system agent.SystemInfo,
	localState *agent.LocalState,
) {
	ticker :=
		time.NewTicker(
			supervisorInterval,
		)

	defer ticker.Stop()

	var worker *deploymentWorker

	for {
		if err :=
			supervisorTick(
				ctx,
				client,
				driver,
				statePath,
				system,
				localState,
				&worker,
			); err != nil {

			if ctx.Err() == nil {
				log.Printf(
					"supervisor tick error: %v",
					err,
				)
			}
		}

		var workerDone <-chan deploymentWorkerResult

		if worker != nil {
			workerDone =
				worker.done
		}

		select {
		case <-ctx.Done():
			if worker != nil {
				log.Printf(
					"agent shutdown: cancelling deployment worker generation=%d execution=%s epoch=%d",
					worker.Generation,
					worker.Execution.ExecutionID,
					worker.Execution.ExecutionEpoch,
				)

				result, stopped :=
					waitForWorkerShutdown(
						worker,
					)

				if !stopped {
					log.Printf(
						"deployment worker did not stop within %s",
						workerShutdownTimeout,
					)

					return
				}

				reportCtx, cancel :=
					context.WithTimeout(
						context.Background(),
						10*time.Second,
					)

				_ =
					handleDeploymentWorkerResult(
						reportCtx,
						client,
						driver,
						statePath,
						system,
						localState,
						result,
					)

				cancel()
			}

			return

		case result :=
			<-workerDone:

			worker = nil

			if err :=
				handleDeploymentWorkerResult(
					ctx,
					client,
					driver,
					statePath,
					system,
					localState,
					result,
				); err != nil {

				log.Printf(
					"deployment worker result error: %v",
					err,
				)
			}

		case <-ticker.C:
		}
	}
}
