//go:build linux

package wireguard

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

type fakeRuntime struct {
	running    bool
	failStart  bool
	failHealth bool
	starts     int
}

func (r *fakeRuntime) Stop(context.Context) error { r.running = false; return nil }
func (r *fakeRuntime) Start(context.Context, model.ServiceSpec, []byte) error {
	r.starts++
	r.running = true
	if r.failStart {
		return errors.New("injected startup failure")
	}
	return nil
}
func (r *fakeRuntime) Healthy(context.Context) error {
	if !r.running || r.failHealth {
		return ErrRuntime
	}
	return nil
}
func testRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("private root-owned state required")
	}
	p, err := os.MkdirTemp("/root", "wg-engine-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(p) })
	return p
}
func desired(gen int64) model.DesiredState {
	k := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	return model.DesiredState{Generation: gen, Core: model.CoreRelease{Type: "wireguard"}, Services: []model.ServiceSpec{{Protocol: "wireguard", Transport: "udp", Security: "wireguard", Listen: "0.0.0.0", Port: 51820, WireGuard: &model.WireGuardSpec{PrivateKey: k}}}}
}
func TestFailedNewGenerationCannotRestoreOldAccess(t *testing.T) {
	root := testRoot(t)
	ctx := context.Background()
	r := &fakeRuntime{}
	e, err := OpenEngine(ctx, root, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconcile(ctx, desired(1)); err != nil {
		t.Fatal(err)
	}
	r.failStart = true
	if err = e.Reconcile(ctx, desired(2)); err == nil || r.running {
		t.Fatal("startup failure left runtime active")
	}
	r.failStart = false
	e, err = OpenEngine(ctx, root, r)
	if err != nil {
		t.Fatal(err)
	}
	starts := r.starts
	if err = e.Reconcile(ctx, desired(1)); err == nil || r.running || r.starts != starts {
		t.Fatal("old assignment restored revoked access")
	}
	conflict := desired(2)
	conflict.Services[0].Port++
	if e.Reconcile(ctx, conflict) == nil {
		t.Fatal("conflicting same generation accepted")
	}
	if err = e.Reconcile(ctx, desired(2)); err != nil {
		t.Fatal(err)
	}
	if e.Health(ctx) != nil {
		t.Fatal("same generation recovery failed")
	}
	empty := desired(3)
	empty.Services = nil
	if err = e.Reconcile(ctx, empty); err != nil || r.running || e.Health(ctx) != nil {
		t.Fatal("empty desired state did not close access")
	}
}
func TestCorruptFenceIsNotReset(t *testing.T) {
	root := testRoot(t)
	ctx := context.Background()
	r := &fakeRuntime{}
	e, err := OpenEngine(ctx, root, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconcile(ctx, desired(1)); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(root+"/checkpoint.json", []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenEngine(ctx, root, r); err == nil || r.running {
		t.Fatal("corrupt fence accepted or access left open")
	}
}
func TestHealthFailureClosesPreviouslyRunningAccess(t *testing.T) {
	root := testRoot(t)
	ctx := context.Background()
	r := &fakeRuntime{}
	e, err := OpenEngine(ctx, root, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconcile(ctx, desired(1)); err != nil {
		t.Fatal(err)
	}
	r.failHealth = true
	if e.Health(ctx) == nil || r.running {
		t.Fatal("failed network verification left access open")
	}
	r.failHealth = false
	if e.Health(ctx) == nil {
		t.Fatal("stopped runtime still reported healthy")
	}
	if err = e.Reconcile(ctx, desired(1)); err != nil {
		t.Fatal(err)
	}
}
func TestCorruptCheckpointDuringReconcileClosesAccess(t *testing.T) {
	root := testRoot(t)
	ctx := context.Background()
	r := &fakeRuntime{}
	e, err := OpenEngine(ctx, root, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Reconcile(ctx, desired(1)); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(root+"/checkpoint.json", []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if e.Reconcile(ctx, desired(2)) == nil || r.running {
		t.Fatal("checkpoint corruption left old access active")
	}
}
func TestTerminalAssignmentCorruptionClosesAccess(t *testing.T) {
	for _, method := range []string{"restore", "confirm"} {
		t.Run(method, func(t *testing.T) {
			root := testRoot(t)
			ctx := context.Background()
			runtime := &fakeRuntime{}
			e, err := OpenEngine(ctx, root, runtime)
			if err != nil {
				t.Fatal(err)
			}
			state := desired(1)
			state.Core.Version = model.WireGuardNativeVersion
			state.Core.DownloadURL = model.WireGuardPinnedDownloadURL
			state.Core.SHA256 = model.WireGuardPinnedSHA256
			if err = e.Reconcile(ctx, state); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(root+"/checkpoint.json", []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
			d := &Driver{engine: e}
			if method == "restore" {
				err = d.RestoreTerminalAssignment(ctx, model.AgentAssignment{DeploymentStatus: "healthy", NodeAppliedGeneration: 1, DesiredState: state, AppliedCoreVersion: model.WireGuardNativeVersion})
			} else {
				err = d.ConfirmHealthyDesired(ctx, state)
			}
			if err == nil || runtime.running {
				t.Fatal("terminal assignment corruption left access open")
			}
		})
	}
}
