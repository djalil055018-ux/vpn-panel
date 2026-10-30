//go:build linux

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

type confirmingTestDriver struct {
	fakeTerminalDriver
	confirm func(context.Context, model.DesiredState) error
}

func (d *confirmingTestDriver) Reconcile(context.Context, model.DesiredState) error { return nil }
func (d *confirmingTestDriver) ConfirmHealthyDesired(ctx context.Context, state model.DesiredState) error {
	return d.confirm(ctx, state)
}

func TestHealthyRuntimeConfirmationFollowsCPCommitAndPrecedesLocalGeneration(t *testing.T) {
	for _, kind := range []string{"success", "cp_failure", "receipt_failure", "deployment_failed"} {
		t.Run(kind, func(t *testing.T) {
			var acknowledged atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "cp_failure" {
					w.WriteHeader(503)
					return
				}
				acknowledged.Store(true)
				w.WriteHeader(204)
			}))
			defer server.Close()
			local := agent.LocalState{AgentToken: "fixture-token", AppliedGeneration: 14}
			path := filepath.Join(t.TempDir(), "state.json")
			if agent.SaveState(path, local) != nil {
				t.Fatal("fixture failed")
			}
			calls := 0
			driver := &confirmingTestDriver{fakeTerminalDriver: fakeTerminalDriver{healthy: true, version: "26.7.28"}}
			driver.confirm = func(ctx context.Context, state model.DesiredState) error {
				calls++
				if !acknowledged.Load() || local.AppliedGeneration != 14 || state.Generation != 15 {
					t.Fatal("confirmation crossed authority/checkpoint boundary")
				}
				if kind == "receipt_failure" {
					return errors.New("injected durable receipt failure")
				}
				return nil
			}
			result := &deploymentWorkerResult{Generation: 15}
			if kind == "deployment_failed" {
				result.Err = errors.New("injected apply failure")
			}
			execution := &leasedExecution{Assignment: leaseTestAssignment("applying", 15, 14), LeaseToken: "fixture-lease", PendingResult: result}
			committed, _, err := commitTerminalWorkerResult(context.Background(), agent.NewClient(server.URL), driver, path, &local, execution)
			if kind == "cp_failure" {
				if err == nil || committed || calls != 0 || local.AppliedGeneration != 14 {
					t.Fatal("rejected CP report became confirmed")
				}
			} else if kind == "receipt_failure" {
				if err == nil || !committed || calls != 1 || local.AppliedGeneration != 14 {
					t.Fatal("missing confirmation advanced local generation")
				}
			} else if kind == "success" {
				if err != nil || !committed || calls != 1 || local.AppliedGeneration != 15 {
					t.Fatal("healthy confirmation failed", err)
				}
			} else if err != nil || !committed || calls != 0 {
				t.Fatal("failed deployment created healthy receipt")
			}
		})
	}
}
