//go:build linux

package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

func TestActualKernelInterruptedPeerUpdateRecoversClosed(t *testing.T) {
	if os.Getenv("VPN_KERNEL_DRIVER_TEST") != "isolated-container" {
		t.Skip("explicit isolated container required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("container guard")
	}
	if _, err := net.InterfaceByName(InterfaceName); err == nil {
		t.Fatal("refusing preexisting interface")
	}
	for stage := 0; stage < 4; stage++ {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			root := testRoot(t)
			ctx := context.Background()
			k, err := OpenKernelRuntime(root, emptyTestPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := k.Stop(ctx); err != nil {
					t.Error(err)
				}
			})
			state := desired(1)
			state.Services[0].Port = 18461
			peer := func(seed, id, address string) model.ClientSpec {
				private := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(seed, 32)))
				public, _ := model.WireGuardPublicKey(private)
				return model.ClientSpec{ID: id, StatsKey: id, WireGuard: &model.WireGuardPeer{PublicKey: public, PresharedKey: private, Address: address}}
			}
			a := peer("a", "11111111-1111-4111-8111-111111111111", "10.66.0.2/32")
			b := peer("b", "22222222-2222-4222-8222-222222222222", "10.66.0.3/32")
			state.Services[0].Clients = []model.ClientSpec{a, b}
			engine, err := OpenEngine(ctx, root, k)
			if err != nil {
				t.Fatal(err)
			}
			if err = engine.Reconcile(ctx, state); err != nil {
				t.Fatal(err)
			}
			before, err := k.readInterface()
			if err != nil {
				t.Fatal(err)
			}
			after := before
			after.Owners = map[string]string{b.WireGuard.PublicKey: b.StatsKey}
			after.Addresses = map[string]string{b.WireGuard.PublicKey: b.WireGuard.Address}
			state.Generation = 2
			state.Services[0].Clients = []model.ClientSpec{b}
			next, _, err := compile(state)
			if err != nil {
				t.Fatal(err)
			}
			if err = engine.save(next); err != nil {
				t.Fatal(err)
			}
			if err = k.saveUpdateJournal(before, after); err != nil {
				t.Fatal(err)
			}
			if stage >= 1 {
				config, err := compiler.CompileKernelWireGuard(state.Services[0])
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, "crash-test.conf")
				if err = writePrivate(path, config); err != nil {
					t.Fatal(err)
				}
				if _, err = kernelCommand(ctx, "/usr/bin/wg", "syncconf", InterfaceName, path); err != nil {
					t.Fatal(err)
				}
			}
			if stage >= 2 {
				raw, err := kernelCommand(ctx, "/usr/bin/wg", "show", InterfaceName, "transfer")
				if err != nil {
					t.Fatal(err)
				}
				peers, err := ParseTransfers(string(raw), after.Owners)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err = k.ledger.Transition(before.Epoch, peers); err != nil {
					t.Fatal(err)
				}
			}
			if stage >= 3 {
				if err = k.saveInterface(after); err != nil {
					t.Fatal(err)
				}
			}
			// New process has no in-memory hints about how far the update got.
			fresh, err := OpenKernelRuntime(root, emptyTestPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenEngine(ctx, root, fresh)
			if err != nil {
				t.Fatal("interrupted update cleanup", err)
			}
			if _, err = net.InterfaceByName(InterfaceName); err == nil {
				t.Fatal("interrupted update stayed open")
			}
			if _, err = os.Stat(filepath.Join(root, "interface-update.json")); !os.IsNotExist(err) {
				t.Fatal("journal not consumed", err)
			}
			old := state
			old.Generation = 1
			if reopened.Reconcile(ctx, old) == nil {
				t.Fatal("old assignment accepted")
			}
			if err = reopened.Reconcile(ctx, state); err != nil {
				t.Fatal("current assignment recovery", err)
			}
			if err = reopened.Health(ctx); err != nil {
				t.Fatal(err)
			}
			if err = reopened.Close(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
