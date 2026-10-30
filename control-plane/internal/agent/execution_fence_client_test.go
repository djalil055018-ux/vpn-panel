package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpn-platform/internal/model"
)

func TestAcknowledgeExecutionFence(
	t *testing.T,
) {
	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					if r.Method !=
						http.MethodPost {

						t.Fatalf(
							"method=%q",
							r.Method,
						)
					}

					if r.URL.Path !=
						"/api/v1/agent/execution/fence-ack" {

						t.Fatalf(
							"path=%q",
							r.URL.Path,
						)
					}

					if r.Header.Get(
						"Authorization",
					) != "Bearer agent-token" {

						t.Fatal(
							"authorization mismatch",
						)
					}

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
						"ram-only-proof" {

						t.Fatal(
							"fence proof mismatch",
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
								ID: input.FenceRequestID,

								NodeID: "11111111-1111-4111-8111-111111111111",

								DeploymentID: input.Execution.DeploymentID,

								Generation: input.Execution.Generation,

								ExecutionID: input.Execution.ExecutionID,

								ExecutionEpoch: input.Execution.ExecutionEpoch,

								State: "acknowledged",

								TargetOwnerInstanceID: input.OwnerInstanceID,
							},
						)
				},
			),
		)

	defer server.Close()

	client :=
		NewClient(
			server.URL,
		)

	requestID :=
		"44444444-4444-4444-8444-444444444444"

	acknowledged, err :=
		client.AcknowledgeExecutionFence(
			context.Background(),
			"agent-token",
			model.ExecutionFenceAckRequest{
				FenceRequestID: requestID,

				Execution: model.ExecutionAssignment{
					DeploymentID: "11111111-1111-4111-8111-111111111111",

					Generation: 15,

					ExecutionID: "22222222-2222-4222-8222-222222222222",

					ExecutionEpoch: 15,
				},

				OwnerInstanceID: "33333333-3333-4333-8333-333333333333",

				FenceProofToken: "ram-only-proof",
			},
		)

	if err != nil {
		t.Fatal(err)
	}

	if acknowledged.ID !=
		requestID {

		t.Fatalf(
			"id=%q want=%q",
			acknowledged.ID,
			requestID,
		)
	}

	if acknowledged.State !=
		"acknowledged" {

		t.Fatalf(
			"state=%q",
			acknowledged.State,
		)
	}
}
