//go:build linux

package wireguard

import (
	"context"
	"net"
	"os"
	"testing"
)

// No-peer lifecycle probe only; this policy deliberately provides no forwarding
// and is not the production network implementation or a network-isolation test.
type emptyTestPolicy struct{}

func (emptyTestPolicy) Prepare(context.Context) error { return nil }
func (emptyTestPolicy) Verify(context.Context) error  { return nil }
func TestActualKernelInterfaceLifecycle(t *testing.T) {
	if os.Getenv("VPN_KERNEL_DRIVER_TEST") != "isolated-container" {
		t.Skip("explicit isolated container required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("container guard")
	}
	if _, err := net.InterfaceByName(InterfaceName); err == nil {
		t.Fatal("refusing preexisting interface")
	}
	root := testRoot(t)
	ctx := context.Background()
	runtime, err := OpenKernelRuntime(root, emptyTestPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	engine, err := OpenEngine(ctx, root, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Reconcile(ctx, desired(1)); err != nil {
		t.Fatal("kernel apply", err)
	}
	if err = engine.Health(ctx); err != nil {
		t.Fatal("kernel health", err)
	}
	if _, err = net.InterfaceByName(InterfaceName); err != nil {
		t.Fatal(err)
	}
	r, err := runtime.readInterface()
	if err != nil {
		t.Fatal(err)
	}
	// A foreign alias must never be adopted or deleted.
	if _, err = kernelCommand(ctx, "/usr/sbin/ip", "link", "set", "dev", InterfaceName, "alias", "foreign-owner"); err != nil {
		t.Fatal(err)
	}
	if runtime.Stop(ctx) == nil {
		t.Fatal("foreign interface stopped")
	}
	if _, err = net.InterfaceByName(InterfaceName); err != nil {
		t.Fatal("foreign interface deleted")
	}
	if _, err = kernelCommand(ctx, "/usr/sbin/ip", "link", "set", "dev", InterfaceName, "alias", "vpn-platform-wireguard-"+r.Epoch); err != nil {
		t.Fatal(err)
	}
	empty := desired(2)
	empty.Services = nil
	if err = engine.Reconcile(ctx, empty); err != nil {
		t.Fatal(err)
	}
	if _, err = net.InterfaceByName(InterfaceName); err == nil {
		t.Fatal("revoke left kernel interface")
	}
	if engine.Reconcile(ctx, desired(1)) == nil {
		t.Fatal("older kernel config replayed")
	}
}
