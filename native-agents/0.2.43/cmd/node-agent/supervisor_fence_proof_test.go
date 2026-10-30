package main

import (
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func fenceProofTestAssignment() model.AgentAssignment {
	return model.AgentAssignment{
		DesiredState: model.DesiredState{
			Generation: 15,

			Core: model.CoreRelease{
				Type:    "xray",
				Version: "26.7.28",
			},
		},

		Execution: model.ExecutionAssignment{
			DeploymentID: "11111111-1111-4111-8111-111111111111",

			Generation: 15,

			ExecutionID: "22222222-2222-4222-8222-222222222222",

			ExecutionEpoch: 15,
		},

		DeploymentStatus: "pending",

		NodeAppliedGeneration: 14,
	}
}

func TestNewLeasedExecutionKeepsSeparateFenceProof(
	t *testing.T,
) {
	const token = "ram-only-lease-proof"

	execution, err :=
		newLeasedExecution(
			fenceProofTestAssignment(),
			"33333333-3333-4333-8333-333333333333",
			model.ExecutionLeaseGrant{
				LeaseToken: token,

				LeaseExpiresAt: time.Now().
					Add(
						time.Minute,
					).
					UTC(),

				RenewAfterSeconds: 15,
			},
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution.LeaseToken !=
		token {

		t.Fatal(
			"authority lease token not initialized",
		)
	}

	if execution.FenceProofToken !=
		token {

		t.Fatal(
			"fence proof token not initialized",
		)
	}
}

func TestMarkLeaseLostRevokesAuthorityButPreservesFenceProof(
	t *testing.T,
) {
	const token = "ram-only-fence-proof"

	cancelled :=
		make(
			chan struct{},
			1,
		)

	execution :=
		&leasedExecution{
			Assignment: fenceProofTestAssignment(),

			LeaseToken: token,

			FenceProofToken: token,

			Worker: &deploymentWorker{
				cancel: func() {
					select {
					case cancelled <- struct{}{}:
					default:
					}
				},
			},
		}

	markLeaseLost(
		execution,
		"unit test",
	)

	if !execution.LeaseLost {
		t.Fatal(
			"lease was not marked lost",
		)
	}

	if execution.LeaseToken != "" {
		t.Fatal(
			"authority lease token survived lease loss",
		)
	}

	if execution.FenceProofToken !=
		token {

		t.Fatal(
			"fence proof was destroyed when authority was revoked",
		)
	}

	select {
	case <-cancelled:

	default:
		t.Fatal(
			"worker cancellation was not requested",
		)
	}
}

func TestClearLeaseSecretsDestroysAuthorityAndFenceProof(
	t *testing.T,
) {
	execution :=
		&leasedExecution{
			LeaseToken: "authority-secret",

			FenceProofToken: "physical-proof-secret",
		}

	clearLeaseSecrets(
		execution,
	)

	if execution.LeaseToken != "" {
		t.Fatal(
			"authority token not cleared",
		)
	}

	if execution.FenceProofToken != "" {
		t.Fatal(
			"fence proof token not cleared",
		)
	}
}

func TestClearLeaseAuthorityDoesNotDestroyFenceProof(
	t *testing.T,
) {
	execution :=
		&leasedExecution{
			LeaseToken: "authority-secret",

			FenceProofToken: "physical-proof-secret",
		}

	clearLeaseAuthority(
		execution,
	)

	if execution.LeaseToken != "" {
		t.Fatal(
			"authority token not cleared",
		)
	}

	if execution.FenceProofToken !=
		"physical-proof-secret" {

		t.Fatal(
			"authority revocation destroyed fence proof",
		)
	}
}
