package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

func fenceProtocolRequest(
	owner string,
) *model.ExecutionFenceRequest {
	assignment :=
		fenceProofTestAssignment()

	return &model.ExecutionFenceRequest{
		ID: "44444444-4444-4444-8444-444444444444",

		DeploymentID: assignment.Execution.DeploymentID,

		Generation: assignment.Execution.Generation,

		ExecutionID: assignment.Execution.ExecutionID,

		ExecutionEpoch: assignment.Execution.ExecutionEpoch,

		State: "requested",

		TargetOwnerInstanceID: owner,

		Reason: "unit test fence",
	}
}

func TestObserveExecutionFenceRevokesAuthorityAndKeepsProof(
	t *testing.T,
) {
	const owner = "33333333-3333-4333-8333-333333333333"

	const proof = "ram-only-proof"

	cancelled :=
		make(
			chan struct{},
			1,
		)

	execution :=
		&leasedExecution{
			Assignment: fenceProofTestAssignment(),

			OwnerInstanceID: owner,

			LeaseToken: proof,

			FenceProofToken: proof,

			Worker: &deploymentWorker{
				cancel: func() {
					select {
					case cancelled <- struct{}{}:
					default:
					}
				},
			},
		}

	err :=
		observeExecutionFence(
			execution,
			fenceProtocolRequest(
				owner,
			),
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution.FenceRequest == nil {
		t.Fatal(
			"fence request was not retained in RAM",
		)
	}

	if !execution.LeaseLost {
		t.Fatal(
			"fence observation did not revoke lease authority",
		)
	}

	if execution.LeaseToken != "" {
		t.Fatal(
			"authority token survived fence observation",
		)
	}

	if execution.FenceProofToken !=
		proof {

		t.Fatal(
			"fence observation destroyed physical proof",
		)
	}

	select {
	case <-cancelled:

	default:
		t.Fatal(
			"fence observation did not cancel worker",
		)
	}
}

func TestObserveExecutionFenceRejectsWrongTargetOwner(
	t *testing.T,
) {
	execution :=
		&leasedExecution{
			Assignment: fenceProofTestAssignment(),

			OwnerInstanceID: "33333333-3333-4333-8333-333333333333",

			LeaseToken: "authority",

			FenceProofToken: "proof",
		}

	err :=
		observeExecutionFence(
			execution,
			fenceProtocolRequest(
				"55555555-5555-4555-8555-555555555555",
			),
		)

	if err == nil {
		t.Fatal(
			"expected wrong target owner rejection",
		)
	}

	if execution.FenceRequest != nil {
		t.Fatal(
			"wrong-owner fence was retained",
		)
	}
}

func TestFenceACKForbiddenBeforeWorkerQuiescence(
	t *testing.T,
) {
	var calls atomic.Int32

	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					calls.Add(1)
					w.WriteHeader(
						http.StatusInternalServerError,
					)
				},
			),
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	const owner = "33333333-3333-4333-8333-333333333333"

	execution :=
		&leasedExecution{
			Assignment: fenceProofTestAssignment(),

			OwnerInstanceID: owner,

			FenceProofToken: "proof",

			LeaseLost: true,

			FenceRequest: fenceProtocolRequest(
				owner,
			),

			Worker: &deploymentWorker{},
		}

	acknowledged, err :=
		acknowledgeObservedExecutionFence(
			context.Background(),
			client,
			&agent.LocalState{
				AgentToken: "agent-token",
			},
			execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if acknowledged {
		t.Fatal(
			"fence acknowledged before worker quiescence",
		)
	}

	if calls.Load() != 0 {
		t.Fatalf(
			"ACK HTTP calls=%d want=0",
			calls.Load(),
		)
	}
}

func TestFenceACKRequiresRAMProof(
	t *testing.T,
) {
	var calls atomic.Int32

	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					calls.Add(1)
				},
			),
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	const owner = "33333333-3333-4333-8333-333333333333"

	execution :=
		&leasedExecution{
			Assignment: fenceProofTestAssignment(),

			OwnerInstanceID: owner,

			LeaseLost: true,

			FenceRequest: fenceProtocolRequest(
				owner,
			),
		}

	acknowledged, err :=
		acknowledgeObservedExecutionFence(
			context.Background(),
			client,
			&agent.LocalState{
				AgentToken: "agent-token",
			},
			execution,
		)

	if err == nil {
		t.Fatal(
			"expected missing RAM proof rejection",
		)
	}

	if acknowledged {
		t.Fatal(
			"missing RAM proof unexpectedly acknowledged",
		)
	}

	if calls.Load() != 0 {
		t.Fatalf(
			"ACK HTTP calls=%d want=0",
			calls.Load(),
		)
	}
}

func TestFenceACKAfterQuiescenceClearsProof(
	t *testing.T,
) {
	const owner = "33333333-3333-4333-8333-333333333333"

	const proof = "ram-only-proof"

	request :=
		fenceProtocolRequest(
			owner,
		)

	var calls atomic.Int32

	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					calls.Add(1)

					var input model.ExecutionFenceAckRequest

					if err :=
						json.NewDecoder(
							r.Body,
						).Decode(
							&input,
						); err != nil {

						t.Fatal(err)
					}

					if input.FenceProofToken !=
						proof {

						t.Fatal(
							"wrong fencing proof sent",
						)
					}

					if input.FenceRequestID !=
						request.ID {

						t.Fatal(
							"wrong fence request id",
						)
					}

					w.Header().Set(
						"Content-Type",
						"application/json",
					)

					_ =
						json.NewEncoder(
							w,
						).Encode(
							model.ExecutionFenceRequest{
								ID: request.ID,

								State: "acknowledged",
							},
						)
				},
			),
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	execution :=
		&leasedExecution{
			Assignment: fenceProofTestAssignment(),

			OwnerInstanceID: owner,

			FenceProofToken: proof,

			LeaseLost: true,

			FenceRequest: request,

			// Worker == nil is the supervisor's observed
			// physical-quiescence state.
			Worker: nil,
		}

	acknowledged, err :=
		acknowledgeObservedExecutionFence(
			context.Background(),
			client,
			&agent.LocalState{
				AgentToken: "agent-token",
			},
			execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if !acknowledged {
		t.Fatal(
			"quiesced execution fence was not acknowledged",
		)
	}

	if calls.Load() != 1 {
		t.Fatalf(
			"ACK HTTP calls=%d want=1",
			calls.Load(),
		)
	}

	if execution.LeaseToken != "" ||
		execution.FenceProofToken != "" {

		t.Fatal(
			"fencing secrets survived successful ACK",
		)
	}
}

func TestValidateLeaseAssignmentRejectsFenceIdentityMismatch(
	t *testing.T,
) {
	assignment :=
		fenceProofTestAssignment()

	assignment.FenceRequest =
		fenceProtocolRequest(
			"33333333-3333-4333-8333-333333333333",
		)

	assignment.FenceRequest.ExecutionEpoch++

	if err :=
		validateLeaseAssignment(
			assignment,
		); err == nil {

		t.Fatal(
			"expected fence identity mismatch rejection",
		)
	}
}

func TestFenceProofRemainsRAMOnlyByConstruction(
	t *testing.T,
) {
	state :=
		agent.LocalState{
			NodeID: "node",

			TenantID: "tenant",

			AgentToken: "agent",

			AppliedGeneration: 15,
		}

	raw, err :=
		json.Marshal(
			state,
		)

	if err != nil {
		t.Fatal(err)
	}

	text :=
		string(raw)

	if text == "" {
		t.Fatal(
			"empty local state JSON",
		)
	}

	// This test intentionally guards field-name regressions,
	// not secret values.
	for _, forbidden := range []string{
		"fence_proof_token",
		"lease_token",
		"owner_instance_id",
	} {

		if containsJSONField(
			text,
			forbidden,
		) {
			t.Fatalf(
				"persistent LocalState unexpectedly contains %q",
				forbidden,
			)
		}
	}
}

func containsJSONField(
	raw string,
	field string,
) bool {
	needle :=
		`"` + field + `"`

	for i := 0; i+len(needle) <= len(raw); i++ {
		if raw[i:i+len(needle)] ==
			needle {

			return true
		}
	}

	return false
}

// Keep time imported in this protocol test so build remains
// explicit if helper timing changes later.
var _ = time.Second
