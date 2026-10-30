package main

import (
	"testing"

	"vpn-platform/internal/model"
)

func TestValidUUIDString(
	t *testing.T,
) {
	if !validUUIDString(
		"ec085729-9fe5-49d3-a064-b9aa32436832",
	) {
		t.Fatal(
			"valid UUID rejected",
		)
	}

	if validUUIDString(
		"not-a-uuid",
	) {
		t.Fatal(
			"invalid UUID accepted",
		)
	}
}

func TestValidateExecutionAssignmentInput(
	t *testing.T,
) {
	execution :=
		model.ExecutionAssignment{
			DeploymentID: "f71a1609-5d27-4806-b774-c084568aa70f",

			Generation: 14,

			ExecutionID: "ec085729-9fe5-49d3-a064-b9aa32436832",

			ExecutionEpoch: 14,
		}

	if !validateExecutionAssignmentInput(
		execution,
	) {
		t.Fatal(
			"valid execution identity rejected",
		)
	}

	execution.ExecutionEpoch = 0

	if validateExecutionAssignmentInput(
		execution,
	) {
		t.Fatal(
			"zero execution epoch accepted",
		)
	}
}
