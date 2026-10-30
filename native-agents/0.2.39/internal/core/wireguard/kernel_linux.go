//go:build linux

package wireguard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

const InterfaceName = "vpnnativewg"

// NetworkPolicy must install and verify the dedicated interface's isolation
// before link-up. A runtime cannot be opened without explicit policy support.
type NetworkPolicy interface {
	Prepare(context.Context) error
	Verify(context.Context) error
}
type interfaceReceipt struct {
	Format     int
	Epoch      string
	Index      int
	Configured bool
	PublicKey  string
	Port       int
	Owners     map[string]string
	Addresses  map[string]string
}
type KernelRuntime struct {
	mu      sync.Mutex
	root    string
	network NetworkPolicy
	ledger  *TrafficLedger
}

func kernelCommand(ctx context.Context, binary string, args ...string) ([]byte, error) {
	raw, err := exec.CommandContext(ctx, binary, args...).Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && filepath.Base(binary) == "ip" {
			return nil, fmt.Errorf("ip %s failed: %w: %s", args[0], err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, fmt.Errorf("%s %s failed: %w", filepath.Base(binary), args[0], err)
	}
	return raw, nil
}
func OpenKernelRuntime(root string, network NetworkPolicy) (*KernelRuntime, error) {
	if network == nil {
		return nil, ErrRuntime
	}
	ledger, err := OpenTrafficLedger(root)
	if err != nil {
		return nil, err
	}
	return &KernelRuntime{root: root, network: network, ledger: ledger}, nil
}
func (k *KernelRuntime) readInterface() (interfaceReceipt, error) {
	var r interfaceReceipt
	raw, err := readPrivate(filepath.Join(k.root, "interface.json"), 1<<24)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(raw, &r) != nil || r.Format != 1 || !epochPattern.MatchString(r.Epoch) || r.Index < 0 || r.Port < 1 || r.Port > 65535 || !model.ValidShadowsocksKey(r.PublicKey) || r.Owners == nil {
		return r, ErrRuntime
	}
	for key, id := range r.Owners {
		if !model.ValidShadowsocksKey(key) || !uuid.MatchString(id) {
			return r, ErrRuntime
		}
	}
	if r.Addresses != nil && !validAddresses(r) {
		return r, ErrRuntime
	}
	return r, nil
}
func (k *KernelRuntime) saveInterface(r interfaceReceipt) error {
	raw, err := json.Marshal(r)
	if err == nil {
		err = writePrivate(filepath.Join(k.root, "interface.json"), raw)
	}
	return err
}
func (k *KernelRuntime) owned(r interfaceReceipt) (*net.Interface, error) {
	iface, err := net.InterfaceByName(InterfaceName)
	if err != nil {
		return nil, err
	}
	alias, err := os.ReadFile("/sys/class/net/" + InterfaceName + "/ifalias")
	if err != nil || strings.TrimSpace(string(alias)) != "vpn-platform-wireguard-"+r.Epoch || (r.Index != 0 && iface.Index != r.Index) {
		return nil, ErrRuntime
	}
	return iface, nil
}
func (k *KernelRuntime) sample(ctx context.Context, r interfaceReceipt) (string, []model.ClientTraffic, error) {
	raw, err := kernelCommand(ctx, "/usr/bin/wg", "show", InterfaceName, "transfer")
	if err != nil {
		return "", nil, err
	}
	peers, err := ParseTransfers(string(raw), r.Owners)
	if err != nil {
		return "", nil, err
	}
	return k.ledger.Sample(r.Epoch, peers)
}
func (k *KernelRuntime) Stop(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	r, err := k.readInterface()
	if os.IsNotExist(err) {
		if _, e := net.InterfaceByName(InterfaceName); e == nil {
			return ErrRuntime
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = net.InterfaceByName(InterfaceName); err != nil {
		return k.finishAbsentUpdate(r)
	}
	if _, err = k.owned(r); err != nil {
		return err
	}
	// Link-down stops payload delivery while preserving peer counters for the
	// final durable sample. A failed sample leaves the interface down for repair.
	if _, err = kernelCommand(ctx, "/usr/sbin/ip", "link", "set", "dev", InterfaceName, "down"); err != nil {
		return err
	}
	if r.Configured {
		if err = k.sampleForStop(ctx, r); err != nil {
			return err
		}
	}
	_, err = kernelCommand(ctx, "/usr/sbin/ip", "link", "delete", "dev", InterfaceName)
	if err == nil {
		err = k.removeUpdateJournal()
	}
	return err
}
func (k *KernelRuntime) Start(ctx context.Context, s model.ServiceSpec, config []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	expected, err := compiler.CompileKernelWireGuard(s)
	if err != nil || !bytes.Equal(expected, config) {
		return ErrRuntime
	}
	if _, err := net.InterfaceByName(InterfaceName); err == nil {
		return ErrRuntime
	}
	if err := k.network.Prepare(ctx); err != nil {
		return err
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	public, err := model.WireGuardPublicKey(s.WireGuard.PrivateKey)
	if err != nil {
		return err
	}
	r := interfaceReceipt{Format: 1, Epoch: hex.EncodeToString(b[:]), PublicKey: public, Port: s.Port, Owners: map[string]string{}, Addresses: map[string]string{}}
	for _, c := range s.Clients {
		if c.WireGuard == nil || !uuid.MatchString(c.StatsKey) {
			return ErrTraffic
		}
		r.Owners[c.WireGuard.PublicKey] = c.StatsKey
		r.Addresses[c.WireGuard.PublicKey] = c.WireGuard.Address
	}
	if err = k.saveInterface(r); err != nil {
		return err
	}
	if _, err = kernelCommand(ctx, "/usr/sbin/ip", "link", "add", "name", InterfaceName, "alias", "vpn-platform-wireguard-"+r.Epoch, "type", "wireguard"); err != nil {
		return err
	}
	iface, err := net.InterfaceByName(InterfaceName)
	if err != nil {
		return err
	}
	r.Index = iface.Index
	if err = k.saveInterface(r); err != nil {
		return err
	}
	if _, err = kernelCommand(ctx, "/usr/sbin/ip", "link", "set", "dev", InterfaceName, "alias", "vpn-platform-wireguard-"+r.Epoch); err != nil {
		return err
	}
	if _, err = k.owned(r); err != nil {
		return err
	}
	for _, address := range []string{"10.66.0.1/32", "fd66::1/128"} {
		if _, err = kernelCommand(ctx, "/usr/sbin/ip", "address", "add", address, "dev", InterfaceName); err != nil {
			return err
		}
	}
	// The link is raised with no key and no peers. Routing requires an UP
	// device; access is enabled only by setconf after all policy/routes verify.
	if _, err = kernelCommand(ctx, "/usr/sbin/ip", "link", "set", "dev", InterfaceName, "up"); err != nil {
		return err
	}
	for _, c := range s.Clients {
		if _, err = kernelCommand(ctx, "/usr/sbin/ip", "route", "add", c.WireGuard.Address, "dev", InterfaceName); err != nil {
			return err
		}
		if _, err = kernelCommand(ctx, "/usr/sbin/ip", "-6", "route", "add", model.WireGuardIPv6Address(c.WireGuard.Address), "dev", InterfaceName); err != nil {
			return err
		}
	}
	if _, err = kernelCommand(ctx, "/usr/sbin/ip", "link", "set", "dev", InterfaceName, "mtu", "1420"); err != nil {
		return err
	}
	if err = k.network.Verify(ctx); err != nil {
		return err
	}
	path := filepath.Join(k.root, "pending.conf")
	if err = writePrivate(path, config); err != nil {
		return err
	}
	defer os.Remove(path)
	if _, err = kernelCommand(ctx, "/usr/bin/wg", "setconf", InterfaceName, path); err != nil {
		return err
	}
	r.Configured = true
	if err = k.saveInterface(r); err != nil {
		return err
	}
	if _, _, err = k.sample(ctx, r); err != nil {
		return err
	}
	return nil
}
func (k *KernelRuntime) Healthy(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	r, err := k.readInterface()
	if err != nil || !r.Configured {
		return ErrRuntime
	}
	iface, err := k.owned(r)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return ErrRuntime
	}
	if err = k.network.Verify(ctx); err != nil {
		return err
	}
	if r.Addresses != nil {
		if err = k.verifyAddresses(ctx, r); err != nil {
			return err
		}
	}
	for field, want := range map[string]string{"public-key": r.PublicKey, "listen-port": strconv.Itoa(r.Port)} {
		got, err := kernelCommand(ctx, "/usr/bin/wg", "show", InterfaceName, field)
		if err != nil || strings.TrimSpace(string(got)) != want {
			return ErrRuntime
		}
	}
	_, _, err = k.sample(ctx, r)
	return err
}
func (k *KernelRuntime) Traffic(ctx context.Context) (string, []model.ClientTraffic, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, err := net.InterfaceByName(InterfaceName); err != nil {
		return k.ledger.Snapshot()
	}
	r, err := k.readInterface()
	if err != nil {
		return "", nil, err
	}
	if _, err = k.owned(r); err != nil {
		return "", nil, err
	}
	return k.sample(ctx, r)
}

var _ ManagedRuntime = (*KernelRuntime)(nil)
