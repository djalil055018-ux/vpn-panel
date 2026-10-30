package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"vpn-platform/internal/model"
)

type blockingReconciler struct {
	started chan struct{}
}

func (
	r *blockingReconciler,
) Reconcile(
	ctx context.Context,
	_ model.DesiredState,
) error {
	close(r.started)

	<-ctx.Done()

	return ctx.Err()
}

type successfulReconciler struct{}

func (
	*successfulReconciler,
) Reconcile(
	context.Context,
	model.DesiredState,
) error {
	return nil
}

func testAssignment(
	generation int64,
) model.AgentAssignment {
	return model.AgentAssignment{
		DesiredState: model.DesiredState{
			Generation: generation,
		},

		Execution: model.ExecutionAssignment{
			DeploymentID: "deployment-test",

			Generation: generation,

			ExecutionID: "execution-test",

			ExecutionEpoch: generation,
		},
	}
}

func TestValidateAssignment(
	t *testing.T,
) {
	assignment :=
		testAssignment(42)

	if err :=
		validateAssignment(
			assignment,
		); err != nil {

		t.Fatal(err)
	}
}

func TestValidateAssignmentGenerationMismatch(
	t *testing.T,
) {
	assignment :=
		testAssignment(42)

	assignment.Execution.Generation =
		41

	if err :=
		validateAssignment(
			assignment,
		); err == nil {

		t.Fatal(
			"expected generation mismatch",
		)
	}
}

func TestSameExecution(
	t *testing.T,
) {
	a :=
		testAssignment(
			42,
		).Execution

	b := a

	if !sameExecution(
		a,
		b,
	) {
		t.Fatal(
			"identical executions do not match",
		)
	}

	b.ExecutionEpoch++

	if sameExecution(
		a,
		b,
	) {
		t.Fatal(
			"different execution epochs matched",
		)
	}
}

func TestDeploymentWorkerCancellation(
	t *testing.T,
) {
	driver :=
		&blockingReconciler{
			started: make(chan struct{}),
		}

	assignment :=
		testAssignment(42)

	worker :=
		startDeploymentWorker(
			context.Background(),
			driver,
			assignment,
		)

	select {
	case <-driver.started:

	case <-time.After(time.Second):
		t.Fatal(
			"worker did not start",
		)
	}

	worker.cancel()

	select {
	case result :=
		<-worker.done:

		if result.Generation !=
			42 {

			t.Fatalf(
				"generation=%d want=42",
				result.Generation,
			)
		}

		if result.Execution.ExecutionID !=
			"execution-test" {

			t.Fatalf(
				"execution=%q",
				result.Execution.ExecutionID,
			)
		}

		if !errors.Is(
			result.Err,
			context.Canceled,
		) {
			t.Fatalf(
				"err=%v want context.Canceled",
				result.Err,
			)
		}

	case <-time.After(time.Second):
		t.Fatal(
			"worker did not stop after cancellation",
		)
	}
}

func TestDeploymentWorkerSuccess(
	t *testing.T,
) {
	worker :=
		startDeploymentWorker(
			context.Background(),
			&successfulReconciler{},
			testAssignment(43),
		)

	select {
	case result :=
		<-worker.done:

		if result.Generation !=
			43 {

			t.Fatalf(
				"generation=%d want=43",
				result.Generation,
			)
		}

		if result.Execution.ExecutionEpoch !=
			43 {

			t.Fatalf(
				"epoch=%d want=43",
				result.Execution.ExecutionEpoch,
			)
		}

		if result.Err != nil {
			t.Fatalf(
				"unexpected error: %v",
				result.Err,
			)
		}

	case <-time.After(time.Second):
		t.Fatal(
			"worker did not complete",
		)
	}
}
