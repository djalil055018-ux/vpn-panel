package xray

import (
	"errors"
	"strings"
	"testing"
)

func TestReconcileFailureBeforeMutationSkipsRollback(
	t *testing.T,
) {
	original :=
		errors.New(
			"staging cancelled",
		)

	rollbackCalled :=
		false

	result :=
		reconcileFailure(
			original,
			false,
			func() error {
				rollbackCalled =
					true

				return nil
			},
		)

	if result != original {
		t.Fatalf(
			"pre-mutation failure changed original error: %v",
			result,
		)
	}

	if rollbackCalled {
		t.Fatal(
			"rollback executed before live data-plane mutation",
		)
	}
}

func TestReconcileFailureAfterMutationRunsRollback(
	t *testing.T,
) {
	original :=
		errors.New(
			"mutation failed",
		)

	rollbackCalled :=
		false

	result :=
		reconcileFailure(
			original,
			true,
			func() error {
				rollbackCalled =
					true

				return nil
			},
		)

	if !rollbackCalled {
		t.Fatal(
			"rollback was not executed after mutation started",
		)
	}

	if !errors.Is(
		result,
		original,
	) {
		t.Fatalf(
			"original error was not preserved: %v",
			result,
		)
	}

	if !strings.Contains(
		result.Error(),
		"rollback successful",
	) {
		t.Fatalf(
			"missing rollback success result: %v",
			result,
		)
	}
}

func TestReconcileFailureAfterMutationReportsRollbackFailure(
	t *testing.T,
) {
	original :=
		errors.New(
			"mutation failed",
		)

	rollbackFailure :=
		errors.New(
			"rollback exploded",
		)

	result :=
		reconcileFailure(
			original,
			true,
			func() error {
				return rollbackFailure
			},
		)

	if !errors.Is(
		result,
		original,
	) {
		t.Fatalf(
			"original error was not preserved: %v",
			result,
		)
	}

	if !strings.Contains(
		result.Error(),
		"rollback failed",
	) {
		t.Fatalf(
			"missing rollback failure result: %v",
			result,
		)
	}

	if !strings.Contains(
		result.Error(),
		rollbackFailure.Error(),
	) {
		t.Fatalf(
			"rollback failure was not reported: %v",
			result,
		)
	}
}
