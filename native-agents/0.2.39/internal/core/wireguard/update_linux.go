//go:build linux

package wireguard

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

func validAddresses(r interfaceReceipt) bool {
	if len(r.Addresses) != len(r.Owners) {
		return false
	}
	pool := netip.MustParsePrefix("10.66.0.0/16")
	seen := map[string]bool{}
	for key, address := range r.Addresses {
		p, err := netip.ParsePrefix(address)
		if id, ok := r.Owners[key]; !ok || !uuid.MatchString(id) || !model.ValidShadowsocksKey(key) || err != nil || p.Bits() != 32 || !pool.Contains(p.Addr()) || address == "10.66.0.1/32" || seen[address] {
			return false
		}
		seen[address] = true
	}
	return true
}

func (k *KernelRuntime) verifyAddresses(ctx context.Context, r interfaceReceipt) error {
	if !validAddresses(r) {
		return ErrRuntime
	}
	raw, err := kernelCommand(ctx, "/usr/bin/wg", "show", InterfaceName, "allowed-ips")
	if err != nil {
		return err
	}
	found := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(strings.ReplaceAll(line, ",", " "))
		if len(parts) != 3 || found[parts[0]] {
			return ErrRuntime
		}
		address, ok := r.Addresses[parts[0]]
		if !ok {
			return ErrRuntime
		}
		v6 := model.WireGuardIPv6Address(address)
		if !((parts[1] == address && parts[2] == v6) || (parts[2] == address && parts[1] == v6)) {
			return ErrRuntime
		}
		found[parts[0]] = true
	}
	if len(found) != len(r.Owners) {
		return ErrRuntime
	}
	return nil
}

// Update never takes the interface down on success. syncconf retains unchanged
// peers' cryptographic sessions, endpoints and counters. Removed peers lose
// access in the kernel before their receipt is published. Any partial failure
// closes the owned interface using an independent deadline.
func (k *KernelRuntime) Update(ctx context.Context, s model.ServiceSpec, config []byte) (applied bool, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	expected, e := compiler.CompileKernelWireGuard(s)
	if e != nil || !bytes.Equal(config, expected) {
		return false, ErrRuntime
	}
	r, e := k.readInterface()
	if e != nil {
		return false, e
	}
	pub, e := model.WireGuardPublicKey(s.WireGuard.PrivateKey)
	if e != nil {
		return false, e
	}
	// Old receipts and server identity changes use the existing full restart path.
	if !r.Configured || r.Addresses == nil || pub != r.PublicKey || s.Port != r.Port {
		return false, nil
	}
	if _, e = k.owned(r); e != nil {
		return false, e
	}
	defer func() {
		if err != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, closeErr := kernelCommand(closeCtx, "/usr/sbin/ip", "link", "set", "dev", InterfaceName, "down")
			err = errors.Join(err, closeErr)
		}
	}()
	if e = k.network.Verify(ctx); e != nil {
		return false, e
	}
	if e = k.verifyAddresses(ctx, r); e != nil {
		return false, e
	}
	next := r
	next.Owners = map[string]string{}
	next.Addresses = map[string]string{}
	oldRoutes := map[string]bool{}
	newRoutes := map[string]bool{}
	for _, address := range r.Addresses {
		oldRoutes[address] = true
	}
	for _, c := range s.Clients {
		if c.WireGuard == nil || !uuid.MatchString(c.StatsKey) {
			return false, ErrTraffic
		}
		key := c.WireGuard.PublicKey
		if oldID, ok := r.Owners[key]; ok && oldID != c.StatsKey {
			return false, ErrTraffic
		}
		next.Owners[key] = c.StatsKey
		next.Addresses[key] = c.WireGuard.Address
		newRoutes[c.WireGuard.Address] = true
	}
	// Sample removed peers before syncconf discards their counters. Bytes arriving
	// between this observation and removal have the same bounded sampling caveat
	// as power loss; surviving peers are measured again without baseline reset.
	if _, _, e = k.sample(ctx, r); e != nil {
		return false, e
	}
	if e = k.saveUpdateJournal(r, next); e != nil {
		return false, e
	}
	for address := range newRoutes {
		if oldRoutes[address] {
			continue
		}
		if _, e = kernelCommand(ctx, "/usr/sbin/ip", "route", "add", address, "dev", InterfaceName); e != nil {
			return false, e
		}
		if _, e = kernelCommand(ctx, "/usr/sbin/ip", "-6", "route", "add", model.WireGuardIPv6Address(address), "dev", InterfaceName); e != nil {
			return false, e
		}
	}
	path := filepath.Join(k.root, "pending.conf")
	if e = writePrivate(path, config); e != nil {
		return false, e
	}
	defer os.Remove(path)
	if _, e = kernelCommand(ctx, "/usr/bin/wg", "syncconf", InterfaceName, path); e != nil {
		return false, e
	}
	raw, e := kernelCommand(ctx, "/usr/bin/wg", "show", InterfaceName, "transfer")
	if e != nil {
		return false, e
	}
	peers, e := ParseTransfers(string(raw), next.Owners)
	if e != nil {
		return false, e
	}
	if _, _, e = k.ledger.Transition(r.Epoch, peers); e != nil {
		return false, e
	}
	if e = k.saveInterface(next); e != nil {
		return false, e
	}
	for address := range oldRoutes {
		if newRoutes[address] {
			continue
		}
		if _, e = kernelCommand(ctx, "/usr/sbin/ip", "route", "delete", address, "dev", InterfaceName); e != nil {
			return false, e
		}
		if _, e = kernelCommand(ctx, "/usr/sbin/ip", "-6", "route", "delete", model.WireGuardIPv6Address(address), "dev", InterfaceName); e != nil {
			return false, e
		}
	}
	if e = k.verifyAddresses(ctx, next); e != nil {
		return false, e
	}
	if e = k.network.Verify(ctx); e != nil {
		return false, e
	}
	if e = k.removeUpdateJournal(); e != nil {
		return false, e
	}
	return true, nil
}
