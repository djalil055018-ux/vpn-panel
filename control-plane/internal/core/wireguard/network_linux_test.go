//go:build linux

package wireguard

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestForwardingPreservesRouterAdvertisementPolicy(t *testing.T) {
	root := t.TempDir()
	for name, value := range map[string]string{"all": "1", "default": "1", "eth0": "1", "lo": "0", "eth1": "2"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "accept_ra"), []byte(value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := preserveRouterAdvertisements(root); err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]string{"all": "2", "default": "2", "eth0": "2", "lo": "0", "eth1": "2"} {
			raw, err := os.ReadFile(filepath.Join(root, name, "accept_ra"))
			if err != nil || strings.TrimSpace(string(raw)) != want {
				t.Fatal("RA policy changed incorrectly", name)
			}
		}
	}
}
func TestNFTPolicyRejectsDriftAndPreservesForeignTables(t *testing.T) {
	if os.Getenv("VPN_KERNEL_DRIVER_TEST") != "isolated-container" {
		t.Skip("explicit isolated container required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("container required")
	}
	ctx := context.Background()
	p := NFTNetwork{}
	if err := p.ProvisionForwarding(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := kernelCommand(ctx, "/usr/sbin/nft", "create", "table", "inet", "vpn_codex_sentinel"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kernelCommand(ctx, "/usr/sbin/nft", "delete", "table", "inet", "vpn_codex_sentinel") })
	if err := p.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := kernelCommand(ctx, "/usr/sbin/nft", "list", "table", "inet", "vpn_codex_sentinel"); err != nil {
		t.Fatal("foreign table changed")
	}
	// Deliberately corrupt only our isolated table. Neither Verify nor Prepare may
	// silently overwrite unknown rules and call the node healthy.
	if _, err := kernelCommand(ctx, "/usr/sbin/nft", "add", "rule", "inet", "vpn_platform_wg", "input", "counter"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
		cmd.Stdin = strings.NewReader("delete table inet vpn_platform_wg\n" + nftRules)
		if cmd.Run() != nil {
			t.Error("restore isolated policy failed")
		}
	})
	if p.Verify(ctx) == nil || p.Prepare(ctx) == nil {
		t.Fatal("modified firewall accepted")
	}
}
