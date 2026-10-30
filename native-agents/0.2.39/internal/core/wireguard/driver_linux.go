//go:build linux

package wireguard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
	"vpn-platform/internal/model"
)

type Driver struct {
	mu         sync.Mutex
	engine     *Engine
	kernel     *KernelRuntime
	BeforeStop func(context.Context)
}

func verifyTools() error {
	for path, want := range map[string]string{"/usr/bin/wg": model.WireGuardToolSHA256, "/usr/sbin/nft": model.WireGuardNFTSHA256} {
		raw, err := os.ReadFile(path)
		if err != nil {
			return ErrRuntime
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			return ErrRuntime
		}
	}
	return nil
}
func nativeState(state model.DesiredState) error {
	if state.Core.Type != "wireguard" || state.Core.Version != model.WireGuardNativeVersion || state.Core.DownloadURL != model.WireGuardPinnedDownloadURL || state.Core.SHA256 != model.WireGuardPinnedSHA256 {
		return ErrRuntime
	}
	return nil
}
func Provision(ctx context.Context, base string) error {
	if err := verifyTools(); err != nil {
		return err
	}
	root := filepath.Join(base, "wireguard")
	if err := privateDirectory(root, true); err != nil {
		return err
	}
	if err := (NFTNetwork{}).ProvisionForwarding(ctx); err != nil {
		return err
	}
	_, err := os.Lstat(filepath.Join(root, "traffic.json"))
	if os.IsNotExist(err) {
		// A missing ledger on a previously assigned node is corruption, not a reset.
		for _, name := range []string{"checkpoint.json", "interface.json"} {
			if _, e := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(e) {
				return ErrTraffic
			}
		}
		l, e := OpenTrafficLedger(root)
		if e != nil {
			return e
		}
		var b [16]byte
		if _, e = rand.Read(b[:]); e != nil {
			return e
		}
		_, _, err = l.Sample(hex.EncodeToString(b[:]), map[string]PeerCounter{})
	}
	return err
}
func Open(ctx context.Context, base string) (*Driver, error) {
	if err := verifyTools(); err != nil {
		return nil, err
	}
	root := filepath.Join(base, "wireguard")
	kernel, err := OpenKernelRuntime(root, NFTNetwork{})
	if err != nil {
		return nil, err
	}
	if _, _, err = kernel.ledger.Snapshot(); err != nil {
		return nil, errors.Join(err, kernel.Stop(ctx))
	}
	engine, err := OpenEngine(ctx, root, kernel)
	if err != nil {
		return nil, err
	}
	return &Driver{engine: engine, kernel: kernel}, nil
}
func (d *Driver) reconcile(ctx context.Context, state model.DesiredState) error {
	if err := nativeState(state); err != nil {
		return err
	}
	if err := verifyTools(); err != nil {
		return err
	}
	if d.BeforeStop != nil {
		d.BeforeStop(ctx)
	}
	err := d.engine.Reconcile(ctx, state)
	// Kernel Stop persisted its final counters after closing the link. Queue those
	// totals even when the new generation is empty or failed to start.
	if d.BeforeStop != nil {
		c, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		d.BeforeStop(c)
		cancel()
	}
	return err
}
func (d *Driver) Reconcile(ctx context.Context, state model.DesiredState) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reconcile(ctx, state)
}
func (d *Driver) Health() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	err := d.engine.Health(ctx)
	return err == nil, err
}
func (d *Driver) CurrentVersion() string {
	d.engine.mu.Lock()
	defer d.engine.mu.Unlock()
	if d.engine.current.Active && !d.engine.current.Empty {
		return model.WireGuardNativeVersion
	}
	return ""
}
func (d *Driver) CoreType() string { return "wireguard" }
func (d *Driver) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if d.BeforeStop != nil {
		d.BeforeStop(ctx)
	}
	err := d.engine.Close(ctx)
	if d.BeforeStop != nil {
		d.BeforeStop(ctx)
	}
	return err
}
func (d *Driver) confirm(ctx context.Context, state model.DesiredState) error {
	if err := nativeState(state); err != nil {
		return err
	}
	want, _, err := compile(state)
	if err != nil {
		return err
	}
	d.engine.mu.Lock()
	defer d.engine.mu.Unlock()
	got, err := d.engine.read()
	if err != nil {
		return d.engine.fail(err)
	}
	if !got.Active || !d.engine.current.Active || got.Generation != want.Generation || got.Digest != want.Digest {
		return ErrRuntime
	}
	if want.Empty {
		return nil
	}
	if err = d.kernel.Healthy(ctx); err != nil {
		return d.engine.fail(err)
	}
	return nil
}
func (d *Driver) ConfirmHealthyDesired(ctx context.Context, state model.DesiredState) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.confirm(ctx, state)
}
func (d *Driver) RestoreTerminalAssignment(ctx context.Context, a model.AgentAssignment) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a.DeploymentStatus != "healthy" || a.FenceRequest != nil || a.NodeAppliedGeneration != a.DesiredState.Generation || nativeState(a.DesiredState) != nil {
		return ErrRuntime
	}
	want, _, err := compile(a.DesiredState)
	if err != nil {
		return err
	}
	version := model.WireGuardNativeVersion
	if want.Empty {
		version = ""
	}
	if a.AppliedCoreVersion != version {
		return ErrRuntime
	}
	got, err := d.engine.read()
	if err != nil {
		d.engine.mu.Lock()
		defer d.engine.mu.Unlock()
		return d.engine.fail(err)
	}
	if !got.Active || got.Generation != want.Generation || got.Digest != want.Digest {
		return ErrRuntime
	}
	d.engine.mu.Lock()
	running := d.engine.current.Active
	d.engine.mu.Unlock()
	if running {
		return d.confirm(ctx, a.DesiredState)
	}
	return d.reconcile(ctx, a.DesiredState)
}
func (d *Driver) Traffic(ctx context.Context) (string, []model.ClientTraffic, error) {
	return d.kernel.Traffic(ctx)
}
func (l *TrafficLedger) Snapshot() (string, []model.ClientTraffic, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := readPrivate(filepath.Join(l.root, "traffic.json"), 32<<20)
	if err != nil {
		return "", nil, err
	}
	var s trafficState
	if json.Unmarshal(raw, &s) != nil || validateTraffic(s) != nil {
		return "", nil, ErrTraffic
	}
	result := make([]model.ClientTraffic, 0, len(s.Totals))
	for id, c := range s.Totals {
		result = append(result, model.ClientTraffic{ClientID: id, Uplink: c.Uplink, Downlink: c.Downlink, ActiveIPsUnavailable: true})
	}
	return s.Epoch, result, nil
}
