package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

func TestLeaseSupervisorRenewsAndExpiresDespiteAssignmentOutage(
	t *testing.T,
) {
	statePath :=
		filepath.Join(
			t.TempDir(),
			"state.json",
		)

	localState, err :=
		integrationLocalState(
			statePath,
		)

	if err != nil {
		t.Fatal(err)
	}

	driver :=
		&integrationLeaseDriver{
			block: true,

			started: make(chan struct{}),

			stopped: make(chan struct{}),
		}

	cp :=
		&integrationCPState{
			deploymentStatus: "pending",

			nodeApplied: 14,
		}

	var assignmentCalls atomic.Int32
	var renewCalls atomic.Int32

	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					switch r.URL.Path {
					case "/api/v1/agent/assignment":
						call :=
							assignmentCalls.Add(1)

						if call > 1 {
							http.Error(
								w,
								"assignment unavailable",
								http.StatusBadGateway,
							)

							return
						}

						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						_ =
							json.NewEncoder(
								w,
							).Encode(
								cp.assignment(),
							)

					case "/api/v1/agent/execution/claim":
						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						_ =
							json.NewEncoder(
								w,
							).Encode(
								model.ExecutionLeaseGrant{
									LeaseToken: "ram-only-lease-token",

									LeaseExpiresAt: time.Now().
										UTC().
										Add(
											3 * time.Second,
										),

									RenewAfterSeconds: 1,
								},
							)

					case "/api/v1/agent/execution/renew":
						renewCalls.Add(1)

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
										UTC().
										Add(
											3 * time.Second,
										),

									RenewAfterSeconds: 1,
								},
							)

					case "/api/v1/agent/deployment-status":
						var report model.DeploymentReport

						if err :=
							json.NewDecoder(
								r.Body,
							).Decode(
								&report,
							); err != nil {

							t.Error(err)
							return
						}

						if report.Status ==
							"applying" {

							cp.setApplying()

							w.WriteHeader(
								http.StatusNoContent,
							)

							return
						}

						http.Error(
							w,
							"unexpected terminal report",
							http.StatusConflict,
						)

					case "/api/v1/agent/health":
						w.WriteHeader(
							http.StatusNoContent,
						)

					default:
						http.NotFound(
							w,
							r,
						)
					}
				},
			),
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	var execution *leasedExecution

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			10*time.Second,
		)

	defer cancel()

	// First tick:
	// assignment -> claim -> applying -> worker.
	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution == nil ||
		execution.Worker == nil {

		t.Fatal(
			"worker not started",
		)
	}

	select {
	case <-driver.started:

	case <-time.After(time.Second):
		t.Fatal(
			"worker did not start",
		)
	}

	time.Sleep(
		1100 * time.Millisecond,
	)

	// From now on assignment is broken.
	// Renew MUST nevertheless happen first.
	_ =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if renewCalls.Load() !=
		1 {

		t.Fatalf(
			"renew_count=%d want=1; assignment outage starved lease renewal",
			renewCalls.Load(),
		)
	}

	if execution.LeaseLost {
		t.Fatal(
			"valid renewed lease unexpectedly lost",
		)
	}

	select {
	case <-driver.stopped:
		t.Fatal(
			"worker stopped while renewed lease remained valid",
		)

	default:
	}

	renewedExpiry :=
		execution.LeaseExpiresAt

	wait :=
		time.Until(
			renewedExpiry,
		) +
			250*time.Millisecond

	if wait > 0 {
		time.Sleep(wait)
	}

	// Assignment is still unavailable, but local expiry must
	// fence execution before assignment is attempted.
	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(
			"local expiry should be enforced independently of assignment endpoint: ",
			err,
		)
	}

	if !execution.LeaseLost {
		t.Fatal(
			"expired lease did not cancel worker while assignment endpoint was unavailable",
		)
	}

	select {
	case <-driver.stopped:

	case <-time.After(time.Second):
		t.Fatal(
			"worker did not quiesce after local lease expiry",
		)
	}

	if driver.reconcileCount.Load() !=
		1 {

		t.Fatalf(
			"reconcile_count=%d want=1",
			driver.reconcileCount.Load(),
		)
	}

	if localState.AppliedGeneration !=
		14 {

		t.Fatalf(
			"applied_generation=%d want=14",
			localState.AppliedGeneration,
		)
	}
}
