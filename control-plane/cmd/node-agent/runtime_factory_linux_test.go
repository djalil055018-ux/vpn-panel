//go:build linux

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/core"
	"vpn-platform/internal/model"
)

func TestRuntimeFactoryRejectsInvalidChoiceAndStatePathWithoutMutation(t *testing.T) {
	for _, choice := range []string{"unknown", "hysteria2"} {
		base := t.TempDir()
		if _, err := openAgentRuntime(context.Background(), choice, base, filepath.Join(base, "custom-state.json"), agent.LocalState{}, nil); err == nil {
			t.Fatal("unsafe runtime selection accepted")
		}
		entries, err := os.ReadDir(base)
		if err != nil || len(entries) != 0 {
			t.Fatal("rejected startup modified data")
		}
	}
}

func TestCancelledPendingReconcileCannotEnableCertificateRestart(t *testing.T) {
	runtime := &pendingHysteriaRuntime{pending: true}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if runtime.Reconcile(ctx, model.DesiredState{}) == nil || !runtime.pending {
		t.Fatal("cancelled bootstrap unlocked runtime")
	}
	if runtime.refreshCertificate(context.Background(), "id", "domain") == nil {
		t.Fatal("certificate restarted pending runtime")
	}
}

func TestHealthyHysteriaIdleAssignmentHasNoRunningCoreVersion(t *testing.T) {
	assignment := model.AgentAssignment{DeploymentStatus: "healthy", NodeAppliedGeneration: 3, DesiredState: model.DesiredState{Generation: 3, Core: model.CoreRelease{Type: "hysteria2", Version: "2.12.2"}}}
	if !healthyHysteriaAssignment(assignment) {
		t.Fatal("intentionally idle assignment rejected")
	}
	assignment.AppliedCoreVersion = "2.12.2"
	if healthyHysteriaAssignment(assignment) {
		t.Fatal("idle node reported running version")
	}
	assignment.DesiredState.Services = []model.ServiceSpec{{}}
	if !healthyHysteriaAssignment(assignment) {
		t.Fatal("running version rejected")
	}
}

func TestAgentStartupOwnershipAndSelectionBeforeRegistration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership")
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
	defer server.Close()
	for _, kind := range []string{"already_owned", "invalid_core", "invalid_hysteria_state", "registration_failure"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("VPN_CONTROL_PLANE", server.URL)
			t.Setenv("VPN_AGENT_DATA", base)
			t.Setenv("VPN_AGENT_STATE", filepath.Join(base, "agent", "state.json"))
			t.Setenv("VPN_BOOTSTRAP_TOKEN", "fixture-only-bootstrap")
			t.Setenv("VPN_RUNTIME_CORE", "xray")
			var release func()
			switch kind {
			case "already_owned":
				var err error
				release, err = core.AcquireNodeOwnership(context.Background(), base)
				if err != nil {
					t.Fatal(err)
				}
			case "invalid_core":
				t.Setenv("VPN_RUNTIME_CORE", "unknown")
			case "invalid_hysteria_state":
				t.Setenv("VPN_RUNTIME_CORE", "hysteria2")
				t.Setenv("VPN_AGENT_STATE", filepath.Join(base, "custom.json"))
			}
			before := calls
			err := runAgent()
			if release != nil {
				release()
			}
			if err == nil {
				t.Fatal("unsafe startup succeeded")
			}
			if kind == "registration_failure" {
				if calls <= before {
					t.Fatal("registration fixture not reached")
				}
			} else if calls != before {
				t.Fatal("rejected startup attempted registration")
			}
			unlock, err := core.AcquireNodeOwnership(context.Background(), base)
			if err != nil {
				t.Fatal("failed startup retained ownership")
			}
			unlock()
		})
	}
}

func TestPendingHysteriaRejectsNonAuthoritativeTerminalAssignments(t *testing.T) {
	for _, assignment := range []model.AgentAssignment{
		{DeploymentStatus: "applying"}, {DeploymentStatus: "failed"}, {DeploymentStatus: "rolled_back"},
		{DeploymentStatus: "healthy", NodeAppliedGeneration: 2, DesiredState: model.DesiredState{Generation: 3}},
		{DeploymentStatus: "healthy", NodeAppliedGeneration: 3, DesiredState: model.DesiredState{Generation: 3, Core: model.CoreRelease{Version: "2.12.2"}}, AppliedCoreVersion: "older"},
		{DeploymentStatus: "healthy", FenceRequest: &model.ExecutionFenceRequest{}},
	} {
		runtime := &pendingHysteriaRuntime{pending: true}
		if runtime.RestoreTerminalAssignment(context.Background(), assignment) == nil || !runtime.pending {
			t.Fatal("unconfirmed terminal assignment activated runtime")
		}
	}
}
