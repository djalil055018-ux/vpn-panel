//go:build linux

package hysteria

import (
	"context"
	"os"
	"testing"
	"vpn-platform/internal/model"
)

func TestTerminalRestoreRejectsChangedAndUncommittedIntentBeforeStart(t *testing.T) {
	for _, kind := range []string{"valid", "older", "newer", "credential", "structure", "policy", "rollback"} {
		t.Run(kind, func(t *testing.T) {
			driver, core, state, _ := driverFixture(t)
			ctx := context.Background()
			switch kind {
			case "older":
				state.Generation = 0
			case "newer":
				state.Generation++
			case "credential":
				state.Services[0].Clients[0].ID = "99999999-9999-4999-8999-999999999999"
			case "structure":
				state.Services[0].Port++
			case "policy":
				changed := state
				changed.Services = append([]model.ServiceSpec(nil), state.Services...)
				changed.Services[0].Clients = nil
				if _, err := driver.transaction.access.policy.Commit(2, clientsForState(changed)); err != nil {
					t.Fatal(err)
				}
			case "rollback":
				state.Generation = 2
				state.Services[0].Port = 444
				candidate, err := driver.prepare(ctx, state)
				if err != nil {
					t.Fatal(err)
				}
				core.failRevision = candidate.id
				if driver.Reconcile(ctx, state) == nil {
					t.Fatal("injected failure accepted")
				}
				core.failRevision = ""
			}
			if core.Stop(ctx) != nil {
				t.Fatal("stop fixture failed")
			}
			driver.transaction.access.synchronized = false
			starts := core.starts
			err := driver.RestoreHealthyDesired(ctx, state)
			if kind == "valid" {
				if err != nil || !core.running || core.starts != starts+1 {
					t.Fatal("healthy durable intent did not restore", err)
				}
			} else if err == nil || core.starts != starts || core.running {
				t.Fatal("changed or rolled-back intent restarted core")
			}
		})
	}
}

func TestTerminalRestorePreservesRenewedTLSAndRejectsShutdown(t *testing.T) {
	driver, core, state, _ := driverFixture(t)
	ctx := context.Background()
	// A local TLS path is never part of the authority supplied by the CP.
	state.Services[0].TLS.CertificateFile = "/not-from-control-plane"
	if err := driver.RestoreHealthyDesired(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := driver.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	starts := core.starts
	if driver.RestoreHealthyDesired(ctx, state) == nil || core.starts != starts {
		t.Fatal("closed lifetime restored")
	}
}

func TestTerminalRestoreIdleKeepsAllCoreProcessesStopped(t *testing.T) {
	driver, core, state, _ := driverFixture(t)
	ctx := context.Background()
	state.Generation++
	state.Services = nil
	if err := driver.Reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	starts := core.starts
	driver.transaction.access.synchronized = false
	if err := driver.RestoreHealthyDesired(ctx, state); err != nil {
		t.Fatal(err)
	}
	if core.running || core.starts != starts || driver.CurrentVersion() != "" {
		t.Fatal("idle restoration started core")
	}
	if healthy, err := driver.Health(); err != nil || !healthy {
		t.Fatal("idle runtime unhealthy")
	}
}

func TestConfirmedRollbackRestorationPreservesLatestRevocations(t *testing.T) {
	for _, kind := range []string{"valid", "missing_receipt", "corrupt_receipt", "wrong_applied", "changed_intent", "wrong_structure", "changed_policy"} {
		t.Run(kind, func(t *testing.T) {
			driver, core, state, _ := driverFixture(t)
			ctx := context.Background()
			if err := driver.ConfirmHealthyDesired(ctx, state); err != nil {
				t.Fatal(err)
			}
			revoked := state.Services[0].Clients[0].ID
			state.Generation = 2
			state.Services[0].Port = 444
			state.Services[0].Clients = nil
			candidate, err := driver.prepare(ctx, state)
			if err != nil {
				t.Fatal(err)
			}
			core.failRevision = candidate.id
			if driver.Reconcile(ctx, state) == nil {
				t.Fatal("failed candidate accepted")
			}
			core.failRevision = ""
			if _, allowed := driver.transaction.access.policy.allowed(revoked); allowed {
				t.Fatal("revocation fixture failed")
			}
			assignment := model.AgentAssignment{DeploymentStatus: "rolled_back", NodeAppliedGeneration: 1, AppliedCoreVersion: PinnedVersion, DesiredState: state}
			switch kind {
			case "missing_receipt":
				os.Remove(driver.confirmed().path)
			case "corrupt_receipt":
				os.WriteFile(driver.confirmed().path, []byte(`{}`), 0600)
			case "wrong_applied":
				assignment.NodeAppliedGeneration = 2
			case "changed_intent":
				assignment.DesiredState.Services = append([]model.ServiceSpec(nil), state.Services...)
				assignment.DesiredState.Services[0].Port++
			case "wrong_structure":
				if driver.transaction.store.activate(ctx, candidate.id) != nil {
					t.Fatal("fixture activation failed")
				}
			case "changed_policy":
				driver.transaction.access.policy.current.Store(&snapshot{allowed: map[[32]byte]string{}})
				bad, _ := buildSnapshot([]Client{{ID: "unexpected", Credential: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}})
				driver.transaction.access.policy.current.Store(bad)
			}
			if core.Stop(ctx) != nil {
				t.Fatal("fixture stop failed")
			}
			driver.transaction.access.synchronized = false
			starts := core.starts
			err = driver.RestoreRolledBackAssignment(ctx, assignment)
			if kind == "valid" {
				if err != nil || !core.running || core.starts != starts+1 {
					t.Fatal("confirmed rollback did not restore", err)
				}
				if _, allowed := driver.transaction.access.policy.allowed(revoked); allowed {
					t.Fatal("restoration regranted revoked credential")
				}
				receipt, _, err := driver.confirmed().read()
				if err != nil || receipt.AppliedGeneration != 1 {
					t.Fatal("rollback advanced healthy confirmation")
				}
			} else if err == nil || core.running || core.starts != starts {
				t.Fatal("unproven rollback started runtime")
			}
		})
	}
}

func TestFailedPreflightRestoresOnlyPreviouslyConfirmedRuntime(t *testing.T) {
	driver, core, state, _ := driverFixture(t)
	ctx := context.Background()
	if driver.ConfirmHealthyDesired(ctx, state) != nil {
		t.Fatal("fixture confirmation failed")
	}
	state.Generation = 2
	driver.validate = func(context.Context, model.DesiredState, int, int) error { return ErrPreflight }
	if driver.Reconcile(ctx, state) == nil {
		t.Fatal("preflight failure accepted")
	}
	core.Stop(ctx)
	driver.transaction.access.synchronized = false
	assignment := model.AgentAssignment{DeploymentStatus: "failed", NodeAppliedGeneration: 1, DesiredState: state}
	if err := driver.RestoreRolledBackAssignment(ctx, assignment); err != nil || !core.running {
		t.Fatal("previously confirmed failed-preflight restore failed", err)
	}
}

func TestCorruptHealthyConfirmationRejectsRestartBeforeMutation(t *testing.T) {
	driver, core, state, _ := driverFixture(t)
	ctx := context.Background()
	if driver.ConfirmHealthyDesired(ctx, state) != nil {
		t.Fatal("fixture confirmation failed")
	}
	os.WriteFile(driver.confirmed().path, []byte(`{}`), 0600)
	core.Stop(ctx)
	driver.transaction.access.synchronized = false
	starts := core.starts
	if driver.RestoreHealthyDesired(ctx, state) == nil || core.running || core.starts != starts {
		t.Fatal("damaged confirmation restarted runtime")
	}
}
