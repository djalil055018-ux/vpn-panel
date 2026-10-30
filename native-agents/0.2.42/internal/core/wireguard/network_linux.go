//go:build linux

package wireguard

import (
	"context"
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Expected output is reviewed against nftables 1.0.9 on Ubuntu 24.04. Output
// differences fail closed; runtime never adopts an arbitrary existing table.
//
//go:embed network.nft
var nftRules string

//go:embed network.expected
var nftExpected string

type NFTNetwork struct{}

func nftListing(ctx context.Context) ([]byte, error) {
	return kernelCommand(ctx, "/usr/sbin/nft", "-s", "-n", "-y", "list", "table", "inet", "vpn_platform_wg")
}
func (NFTNetwork) verifyRules(ctx context.Context) error {
	raw, err := nftListing(ctx)
	if err != nil {
		return err
	}
	if strings.Join(strings.Fields(string(raw)), " ") != strings.Join(strings.Fields(nftExpected), " ") {
		return ErrRuntime
	}
	return nil
}
func (n NFTNetwork) Prepare(ctx context.Context) error {
	if _, err := nftListing(ctx); err != nil {
		// `create table` rejects a preexisting name. The transaction contains only
		// this dedicated table, never flush ruleset or changes to unrelated tables.
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
		cmd.Stdin = strings.NewReader(nftRules)
		if err = cmd.Run(); err != nil {
			return ErrRuntime
		}
	}
	return n.Verify(ctx)
}
func (n NFTNetwork) Verify(ctx context.Context) error {
	if err := n.verifyRules(ctx); err != nil {
		return err
	}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		raw, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(raw)) != "1" {
			return ErrRuntime
		}
	}
	return nil
}

// Keep existing IPv6 router-advertisement clients working after forwarding is
// enabled. Explicitly disabled RA (0) and router-capable RA (2) stay unchanged.
// Updating default also covers interfaces created after boot provisioning.
func preserveRouterAdvertisements(conf string) error {
	entries, err := os.ReadDir(conf)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(conf, entry.Name(), "accept_ra")
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		switch strings.TrimSpace(string(raw)) {
		case "0", "2":
		case "1":
			if err = os.WriteFile(path, []byte("2\n"), 0644); err != nil {
				return err
			}
		default:
			return ErrRuntime
		}
	}
	return nil
}

// ProvisionForwarding is explicit installer/boot preparation for a dedicated
// native node. Ordinary reconciliation never changes host forwarding policy.
func (n NFTNetwork) ProvisionForwarding(ctx context.Context) error {
	if _, err := nftListing(ctx); err != nil {
		cmd := exec.CommandContext(ctx, "/usr/sbin/nft", "-f", "-")
		cmd.Stdin = strings.NewReader(nftRules)
		if cmd.Run() != nil {
			return ErrRuntime
		}
	}
	if err := n.verifyRules(ctx); err != nil {
		return err
	}
	if err := preserveRouterAdvertisements("/proc/sys/net/ipv6/conf"); err != nil {
		return err
	}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
			return err
		}
	}
	return n.Verify(ctx)
}
