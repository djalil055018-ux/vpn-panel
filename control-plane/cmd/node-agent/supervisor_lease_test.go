package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

func TestLeaseSupervisorHealthIncludesMetrics(t *testing.T) {
	originalCollector := collectNodeMetrics
	t.Cleanup(func() { collectNodeMetrics = originalCollector })
	collectNodeMetrics = func() *model.NodeMetrics {
		return &model.NodeMetrics{
			CPUPercent: 12.5, Load1: 0.4,
			MemoryTotal: 8_000, MemoryUsed: 3_000,
			DiskTotal: 50_000, DiskUsed: 10_000,
			NetworkRX: 123, NetworkTX: 456, UptimeSeconds: 789,
		}
	}
	var received model.HealthReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/health" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected health request")
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode health report: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := agent.NewClient(server.URL)
	state := &agent.LocalState{AgentToken: "test-token", AppliedGeneration: 7}
	err := sendLeaseSupervisorHealth(
		context.Background(), client, &fakeTerminalDriver{healthy: true, version: "26.7.28"},
		agent.SystemInfo{OSName: "linux", OSVersion: "24.04", Architecture: "amd64"},
		state, true, "healthy",
	)
	if err != nil {
		t.Fatal(err)
	}
	if received.Metrics == nil || received.Metrics.CPUPercent != 12.5 || received.Metrics.NetworkTX != 456 {
		t.Fatalf("lease supervisor health omitted metrics: %+v", received.Metrics)
	}
}

type fakeTerminalDriver struct {
	healthy bool
	err     error
	version string
}

func (
	d *fakeTerminalDriver,
) Health() (
	bool,
	error,
) {
	return d.healthy,
		d.err
}

func (
	d *fakeTerminalDriver,
) CurrentVersion() string {
	return d.version
}

func leaseTestAssignment(
	status string,
	generation int64,
	applied int64,
) model.AgentAssignment {
	return model.AgentAssignment{
		DesiredState: model.DesiredState{
			Generation: generation,

			Core: model.CoreRelease{
				Type: "xray",

				Version: "26.7.28",
			},
		},

		Execution: model.ExecutionAssignment{
			DeploymentID: "11111111-1111-4111-8111-111111111111",

			Generation: generation,

			ExecutionID: "22222222-2222-4222-8222-222222222222",

			ExecutionEpoch: generation,
		},

		DeploymentStatus: status,

		NodeAppliedGeneration: applied,

		AppliedCoreVersion: "26.7.28",
	}
}

func TestValidateLeaseAssignmentPending(
	t *testing.T,
) {
	assignment :=
		leaseTestAssignment(
			"pending",
			15,
			14,
		)

	if err :=
		validateLeaseAssignment(
			assignment,
		); err != nil {

		t.Fatal(err)
	}
}

func TestValidateLeaseAssignmentHealthy(
	t *testing.T,
) {
	assignment :=
		leaseTestAssignment(
			"healthy",
			15,
			15,
		)

	if err :=
		validateLeaseAssignment(
			assignment,
		); err != nil {

		t.Fatal(err)
	}
}

func TestValidateLeaseAssignmentRejectsPendingAlreadyApplied(
	t *testing.T,
) {
	assignment :=
		leaseTestAssignment(
			"pending",
			15,
			15,
		)

	if err :=
		validateLeaseAssignment(
			assignment,
		); err == nil {

		t.Fatal(
			"expected inconsistent pending assignment rejection",
		)
	}
}

func TestNonRetryableLeaseHTTPError(
	t *testing.T,
) {
	conflict :=
		&agent.HTTPStatusError{
			StatusCode: http.StatusConflict,

			Status: "409 Conflict",
		}

	if !nonRetryableLeaseHTTPError(
		conflict,
	) {
		t.Fatal(
			"409 must be non-retryable",
		)
	}

	serverError :=
		&agent.HTTPStatusError{
			StatusCode: http.StatusBadGateway,

			Status: "502 Bad Gateway",
		}

	if nonRetryableLeaseHTTPError(
		serverError,
	) {
		t.Fatal(
			"502 must remain retryable until lease expiry",
		)
	}

	if nonRetryableLeaseHTTPError(
		errors.New(
			"network failure",
		),
	) {
		t.Fatal(
			"network failure must remain retryable until lease expiry",
		)
	}
}

func TestRecoverHealthyTerminalAssignment(
	t *testing.T,
) {
	statePath :=
		filepath.Join(
			t.TempDir(),
			"state.json",
		)

	state :=
		agent.LocalState{
			NodeID: "node-test",

			AgentToken: "agent-token",

			AppliedGeneration: 14,
		}

	assignment :=
		leaseTestAssignment(
			"healthy",
			15,
			15,
		)

	recovered, err :=
		recoverTerminalAssignment(
			&fakeTerminalDriver{
				healthy: true,

				version: "26.7.28",
			},
			statePath,
			&state,
			assignment,
		)

	if err != nil {
		t.Fatal(err)
	}

	if !recovered {
		t.Fatal(
			"healthy assignment not recovered",
		)
	}

	if state.AppliedGeneration !=
		15 {

		t.Fatalf(
			"applied=%d want=15",
			state.AppliedGeneration,
		)
	}

	loaded, err :=
		agent.LoadState(
			statePath,
		)

	if err != nil {
		t.Fatal(err)
	}

	if loaded.AppliedGeneration !=
		15 {

		t.Fatalf(
			"persisted applied=%d want=15",
			loaded.AppliedGeneration,
		)
	}
}

func TestRecoverHealthyTerminalRejectsWrongLocalCore(
	t *testing.T,
) {
	state :=
		agent.LocalState{
			AppliedGeneration: 14,
		}

	assignment :=
		leaseTestAssignment(
			"healthy",
			15,
			15,
		)

	_, err :=
		recoverTerminalAssignment(
			&fakeTerminalDriver{
				healthy: true,

				version: "26.7.11",
			},
			filepath.Join(
				t.TempDir(),
				"state.json",
			),
			&state,
			assignment,
		)

	if err == nil {
		t.Fatal(
			"wrong local core version unexpectedly recovered",
		)
	}

	if state.AppliedGeneration !=
		14 {

		t.Fatalf(
			"local state mutated after failed recovery: %d",
			state.AppliedGeneration,
		)
	}
}

func TestRecoverRolledBackTerminalAssignment(
	t *testing.T,
) {
	statePath :=
		filepath.Join(
			t.TempDir(),
			"state.json",
		)

	state :=
		agent.LocalState{
			NodeID: "node-test",

			AppliedGeneration: 14,
		}

	assignment :=
		leaseTestAssignment(
			"rolled_back",
			15,
			14,
		)

	recovered, err :=
		recoverTerminalAssignment(
			&fakeTerminalDriver{},
			statePath,
			&state,
			assignment,
		)

	if err != nil {
		t.Fatal(err)
	}

	if !recovered {
		t.Fatal(
			"rolled_back assignment not recovered",
		)
	}

	if state.AppliedGeneration !=
		14 {

		t.Fatalf(
			"applied=%d want=14",
			state.AppliedGeneration,
		)
	}

	if state.FailedGeneration !=
		15 {

		t.Fatalf(
			"failed=%d want=15",
			state.FailedGeneration,
		)
	}
}
