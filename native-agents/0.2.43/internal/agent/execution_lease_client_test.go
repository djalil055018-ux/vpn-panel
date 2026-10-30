package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func testExecutionAssignment() model.ExecutionAssignment {
	return model.ExecutionAssignment{
		DeploymentID: "11111111-1111-4111-8111-111111111111",

		Generation: 15,

		ExecutionID: "22222222-2222-4222-8222-222222222222",

		ExecutionEpoch: 15,
	}
}

func TestClaimExecutionLease(
	t *testing.T,
) {
	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					if r.URL.Path !=
						"/api/v1/agent/execution/claim" {

						t.Fatalf(
							"path=%q",
							r.URL.Path,
						)
					}

					if r.Method !=
						http.MethodPost {

						t.Fatalf(
							"method=%q",
							r.Method,
						)
					}

					if r.Header.Get(
						"Authorization",
					) != "Bearer agent-token" {

						t.Fatal(
							"authorization header mismatch",
						)
					}

					var request model.ExecutionLeaseClaimRequest

					if err :=
						json.NewDecoder(
							r.Body,
						).Decode(
							&request,
						); err != nil {

						t.Fatal(err)
					}

					if request.OwnerInstanceID !=
						"33333333-3333-4333-8333-333333333333" {

						t.Fatalf(
							"owner=%q",
							request.OwnerInstanceID,
						)
					}

					if request.Execution.Generation !=
						15 {

						t.Fatalf(
							"generation=%d",
							request.Execution.Generation,
						)
					}

					w.Header().Set(
						"Content-Type",
						"application/json",
					)

					_, _ =
						w.Write(
							[]byte(
								`{
									"lease_token":"lease-secret",
									"lease_expires_at":"2026-08-26T20:00:00Z",
									"renew_after_seconds":15
								}`,
							),
						)
				},
			),
		)

	defer server.Close()

	client :=
		NewClient(
			server.URL,
		)

	grant, err :=
		client.ClaimExecutionLease(
			context.Background(),
			"agent-token",
			model.ExecutionLeaseClaimRequest{
				Execution: testExecutionAssignment(),

				OwnerInstanceID: "33333333-3333-4333-8333-333333333333",
			},
		)

	if err != nil {
		t.Fatal(err)
	}

	if grant.LeaseToken !=
		"lease-secret" {

		t.Fatal(
			"lease token mismatch",
		)
	}

	if grant.RenewAfterSeconds !=
		15 {

		t.Fatalf(
			"renew_after=%d",
			grant.RenewAfterSeconds,
		)
	}

	if grant.LeaseExpiresAt.IsZero() {
		t.Fatal(
			"lease expiry is zero",
		)
	}
}

func TestRenewExecutionLease(
	t *testing.T,
) {
	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					var request model.ExecutionLeaseRenewRequest

					if err :=
						json.NewDecoder(
							r.Body,
						).Decode(
							&request,
						); err != nil {

						t.Fatal(err)
					}

					if request.LeaseToken !=
						"lease-secret" {

						t.Fatal(
							"renew lease token mismatch",
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
							model.ExecutionLeaseGrant{
								LeaseExpiresAt: time.Now().
									Add(
										time.Minute,
									).
									UTC(),

								RenewAfterSeconds: 15,
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

	grant, err :=
		client.RenewExecutionLease(
			context.Background(),
			"agent-token",
			model.ExecutionLeaseRenewRequest{
				Execution: testExecutionAssignment(),

				OwnerInstanceID: "33333333-3333-4333-8333-333333333333",

				LeaseToken: "lease-secret",
			},
		)

	if err != nil {
		t.Fatal(err)
	}

	if grant.RenewAfterSeconds !=
		15 {

		t.Fatalf(
			"renew_after=%d",
			grant.RenewAfterSeconds,
		)
	}
}

func TestRenewExecutionLeaseConflict(
	t *testing.T,
) {
	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					http.Error(
						w,
						`{"error":"execution lease conflict"}`,
						http.StatusConflict,
					)
				},
			),
		)

	defer server.Close()

	client :=
		NewClient(
			server.URL,
		)

	_, err :=
		client.RenewExecutionLease(
			context.Background(),
			"agent-token",
			model.ExecutionLeaseRenewRequest{
				Execution: testExecutionAssignment(),

				OwnerInstanceID: "33333333-3333-4333-8333-333333333333",

				LeaseToken: "lease-secret",
			},
		)

	if err == nil {
		t.Fatal(
			"expected renew conflict",
		)
	}

	status, ok :=
		HTTPErrorStatus(err)

	if !ok {
		t.Fatalf(
			"expected HTTPStatusError, got %T",
			err,
		)
	}

	if status !=
		http.StatusConflict {

		t.Fatalf(
			"status=%d",
			status,
		)
	}
}
