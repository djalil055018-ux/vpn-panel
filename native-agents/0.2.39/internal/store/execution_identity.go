package store

import (
	"errors"
	"fmt"

	"vpn-platform/internal/model"
)

var (
	ErrExecutionIdentityIncomplete = errors.New(
		"deployment execution identity incomplete",
	)

	ErrExecutionIdentityMismatch = errors.New(
		"deployment execution identity mismatch",
	)
)

func deploymentReportHasAnyExecutionIdentity(
	report model.DeploymentReport,
) bool {
	return report.DeploymentID != "" ||
		report.ExecutionID != "" ||
		report.ExecutionEpoch != 0
}

func validateDeploymentExecutionIdentity(
	report model.DeploymentReport,
	expectedDeploymentID string,
	expectedExecutionID string,
	expectedExecutionEpoch int64,
) error {
	// D3A backward compatibility:
	// legacy Agents that send no execution identity at all
	// are still accepted temporarily.
	if !deploymentReportHasAnyExecutionIdentity(
		report,
	) {
		return nil
	}

	if report.DeploymentID == "" ||
		report.ExecutionID == "" ||
		report.ExecutionEpoch < 1 {

		return ErrExecutionIdentityIncomplete
	}

	if report.DeploymentID !=
		expectedDeploymentID ||
		report.ExecutionID !=
			expectedExecutionID ||
		report.ExecutionEpoch !=
			expectedExecutionEpoch {

		return fmt.Errorf(
			"%w: generation=%d",
			ErrExecutionIdentityMismatch,
			report.Generation,
		)
	}

	return nil
}
