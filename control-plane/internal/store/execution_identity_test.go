package store

import (
	"errors"
	"testing"

	"vpn-platform/internal/model"
)

func TestDeploymentExecutionIdentityLegacyAllowed(
	t *testing.T,
) {
	err :=
		validateDeploymentExecutionIdentity(
			model.DeploymentReport{
				Generation: 14,
			},
			"deployment-a",
			"execution-a",
			14,
		)

	if err != nil {
		t.Fatalf(
			"legacy report rejected: %v",
			err,
		)
	}
}

func TestDeploymentExecutionIdentityExactMatch(
	t *testing.T,
) {
	err :=
		validateDeploymentExecutionIdentity(
			model.DeploymentReport{
				Generation: 14,

				DeploymentID: "deployment-a",

				ExecutionID: "execution-a",

				ExecutionEpoch: 14,
			},
			"deployment-a",
			"execution-a",
			14,
		)

	if err != nil {
		t.Fatalf(
			"exact identity rejected: %v",
			err,
		)
	}
}

func TestDeploymentExecutionIdentityIncomplete(
	t *testing.T,
) {
	err :=
		validateDeploymentExecutionIdentity(
			model.DeploymentReport{
				Generation: 14,

				ExecutionID: "execution-a",
			},
			"deployment-a",
			"execution-a",
			14,
		)

	if !errors.Is(
		err,
		ErrExecutionIdentityIncomplete,
	) {
		t.Fatalf(
			"err=%v want incomplete",
			err,
		)
	}
}

func TestDeploymentExecutionIdentityMismatch(
	t *testing.T,
) {
	err :=
		validateDeploymentExecutionIdentity(
			model.DeploymentReport{
				Generation: 14,

				DeploymentID: "deployment-a",

				ExecutionID: "OLD-EXECUTION",

				ExecutionEpoch: 14,
			},
			"deployment-a",
			"execution-a",
			14,
		)

	if !errors.Is(
		err,
		ErrExecutionIdentityMismatch,
	) {
		t.Fatalf(
			"err=%v want mismatch",
			err,
		)
	}
}
