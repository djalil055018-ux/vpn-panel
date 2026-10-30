//go:build linux

package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"strings"
	"testing"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

func TestActualKernelDriverTunnel(t *testing.T) {
	if os.Getenv("VPN_KERNEL_DRIVER_TEST") != "isolated-container" {
		t.Skip("isolated container required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("container required")
	}
	root := os.Getenv("VPN_KERNEL_E2E_DIR")
	if !strings.HasPrefix(root, "/root/vpn-wg-driver-e2e-") || filepath.Clean(root) != root {
		t.Skip("dedicated fixture directory required")
	}
	if err := privateDirectory(root, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	key := func() string {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(b[:])
	}
	server, client, psk := key(), key(), key()
	sp, _ := model.WireGuardPublicKey(server)
	cp, _ := model.WireGuardPublicKey(client)
	state := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: "wireguard", Version: model.WireGuardNativeVersion, DownloadURL: model.WireGuardPinnedDownloadURL, SHA256: model.WireGuardPinnedSHA256}, Services: []model.ServiceSpec{{ID: "11111111-1111-4111-8111-111111111111", Protocol: "wireguard", Transport: "udp", Security: "wireguard", Listen: "0.0.0.0", Port: 18459, WireGuard: &model.WireGuardSpec{PrivateKey: server}, Clients: []model.ClientSpec{{ID: "22222222-2222-4222-8222-222222222222", StatsKey: "22222222-2222-4222-8222-222222222222", WireGuard: &model.WireGuardPeer{PublicKey: cp, PresharedKey: psk, Address: "10.66.0.2/32"}}}}}}
	profile, err := compiler.WireGuardProfile(client, sp, psk, "10.66.0.2/32", "127.0.0.1", 18459)
	if err != nil {
		t.Fatal(err)
	}
	if err = writePrivate(filepath.Join(root, "client.conf"), []byte(profile)); err != nil {
		t.Fatal(err)
	}
	if err = Provision(ctx, root); err != nil {
		t.Fatal(err)
	}
	driver, err := Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	runtime := driver.kernel
	t.Cleanup(func() {
		if err := driver.Close(); err != nil {
			t.Error(err)
		}
	})
	advance := func(n int) {
		if err := writePrivate(filepath.Join(root, fmt.Sprintf("ready-%d", n)), []byte("ready")); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := os.Stat(filepath.Join(root, "abort")); err == nil {
				t.Fatal("orchestrator aborted")
			}
			if _, err := os.Stat(filepath.Join(root, fmt.Sprintf("advance-%d", n))); err == nil {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("orchestrator did not complete phase", n)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if err = driver.Reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	advance(1)
	_, before, err := runtime.Traffic(ctx)
	if err != nil || len(before) != 1 || before[0].Uplink <= 0 || before[0].Downlink <= 0 {
		t.Fatal("missing native peer traffic", err)
	}
	peer := state.Services[0].Clients[0]
	state.Generation = 2
	state.Services[0].Clients = nil
	if err = driver.Reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	advance(2)
	state.Generation = 3
	state.Services[0].Clients = []model.ClientSpec{peer}
	if err = driver.Reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	advance(3)
	epoch, after, err := runtime.Traffic(ctx)
	if err != nil || len(after) != 1 || after[0].Uplink <= before[0].Uplink || after[0].Downlink <= before[0].Downlink {
		t.Fatal("traffic lost across native revoke/restore", err)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}
	// A terminal restore must match the last confirmed receipt exactly.
	driver, err = Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	assignment := model.AgentAssignment{DeploymentStatus: "healthy", DesiredState: state, NodeAppliedGeneration: state.Generation, AppliedCoreVersion: model.WireGuardNativeVersion}
	bad := assignment
	bad.AppliedCoreVersion = "wrong"
	if driver.RestoreTerminalAssignment(ctx, bad) == nil {
		t.Fatal("wrong runtime version restored")
	}
	bad = assignment
	bad.DesiredState.Generation--
	if driver.RestoreTerminalAssignment(ctx, bad) == nil {
		t.Fatal("stale terminal state restored")
	}
	if err = driver.RestoreTerminalAssignment(ctx, assignment); err != nil {
		t.Fatal("healthy terminal restore", err)
	}
	if err = driver.ConfirmHealthyDesired(ctx, state); err != nil {
		t.Fatal("desired receipt mismatch", err)
	}
	advance(4)
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}
	// Reload persisted accounting after interface removal without resetting it.
	l, err := OpenTrafficLedger(filepath.Join(root, "wireguard"))
	if err != nil {
		t.Fatal(err)
	}
	savedEpoch, saved, err := l.Snapshot()
	if err != nil || savedEpoch != epoch || saved[0].Uplink < after[0].Uplink || saved[0].Downlink < after[0].Downlink {
		t.Fatal("final accounting persistence", err)
	}
	t.Logf("NATIVE_DRIVER_TUNNEL_REVOKE_RESTORE_ACCOUNTING_PASS up=%d down=%d", saved[0].Uplink, saved[0].Downlink)
}
