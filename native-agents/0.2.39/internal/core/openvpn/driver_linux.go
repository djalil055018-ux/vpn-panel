//go:build linux

package openvpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

const ManagedService = "vpn-platform-openvpn.service"
const AgentExecutable = "/usr/local/bin/vpn-node-agent"

var safePath = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)

type checkpoint struct {
	Generation int64
	Digest     string
	Active     bool
	Empty      bool
}
type Driver struct {
	root       string
	gate       chan struct{}
	mu         sync.RWMutex
	current    checkpoint
	BeforeStop func(context.Context)
}

func verifyBinary(ctx context.Context) error {
	raw, err := os.ReadFile("/usr/sbin/openvpn")
	if err != nil {
		return ErrRuntime
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != model.OpenVPNBinarySHA256 {
		return ErrRuntime
	}
	raw, err = exec.CommandContext(ctx, "/usr/sbin/openvpn", "--version").Output()
	if err != nil || !strings.HasPrefix(string(raw), "OpenVPN "+model.OpenVPNPinnedVersion+" ") {
		return ErrRuntime
	}
	return nil
}
func unit(ctx context.Context, args ...string) (string, error) {
	raw, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	return strings.TrimSpace(string(raw)), err
}
func Open(ctx context.Context, base string) (*Driver, error) {
	root := filepath.Join(base, "openvpn")
	if err := privateDirectory(root, false); err != nil {
		return nil, err
	}
	if err := verifyBinary(ctx); err != nil {
		return nil, err
	}
	if err := VerifyNetwork(ctx); err != nil {
		return nil, err
	}
	d := &Driver{root: root, gate: make(chan struct{}, 1)}
	if _, err := d.readCheckpoint(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return d, nil
}
func (d *Driver) readCheckpoint() (checkpoint, error) {
	var c checkpoint
	raw, err := readPrivate(filepath.Join(d.root, "checkpoint.json"), 4096)
	if err != nil {
		return c, err
	}
	if json.Unmarshal(raw, &c) != nil || c.Generation <= 0 || len(c.Digest) != 64 {
		return c, ErrRuntime
	}
	return c, nil
}
func (d *Driver) saveCheckpoint(c checkpoint) error {
	raw, err := json.Marshal(c)
	if err == nil {
		err = writePrivate(filepath.Join(d.root, "checkpoint.json"), raw)
	}
	if err == nil {
		d.mu.Lock()
		d.current = c
		d.mu.Unlock()
	}
	return err
}
func desiredCheckpoint(state model.DesiredState) (checkpoint, error) {
	if state.Generation <= 0 || state.Core.Type != "openvpn" || state.Core.Version != model.OpenVPNPinnedVersion || state.Core.SHA256 != model.OpenVPNPinnedSHA256 || state.Core.DownloadURL != model.OpenVPNPinnedDownloadURL || len(state.Services) > 1 {
		return checkpoint{}, ErrRuntime
	}
	for _, s := range state.Services {
		if err := compiler.ValidateOpenVPNService(s, time.Now().UTC()); err != nil {
			return checkpoint{}, err
		}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return checkpoint{}, err
	}
	sum := sha256.Sum256(raw)
	return checkpoint{Generation: state.Generation, Digest: hex.EncodeToString(sum[:]), Empty: len(state.Services) == 0}, nil
}
func (d *Driver) lock(ctx context.Context) error {
	select {
	case d.gate <- struct{}{}:
		if ctx.Err() != nil {
			<-d.gate
			return ctx.Err()
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (d *Driver) stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if d.BeforeStop != nil {
		d.BeforeStop(ctx)
	}
	_, err := unit(ctx, "stop", ManagedService)
	if d.BeforeStop != nil {
		d.BeforeStop(ctx)
	}
	return err
}

// Persist a high-water fence before stopping the previous process. Any failure
// after that point leaves access closed and cannot restore an older generation.
func (d *Driver) Reconcile(ctx context.Context, state model.DesiredState) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	next, err := desiredCheckpoint(state)
	if err != nil {
		return err
	}
	prior, err := d.readCheckpoint()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if next.Generation < prior.Generation || (next.Generation == prior.Generation && next.Digest != prior.Digest) {
		return ErrRuntime
	}
	// Restarting an already committed identical generation cannot restore revoked
	// access. Preserve its receipt across interrupted startup so the next agent
	// can retry. A NEW generation still persists an inactive fence before stopping.
	next.Active = prior.Active && prior.Generation == next.Generation && prior.Digest == next.Digest
	if err = verifyBinary(ctx); err != nil {
		return err
	}
	if err = VerifyNetwork(ctx); err != nil {
		return err
	}
	if err = d.saveCheckpoint(next); err != nil {
		return err
	}
	if err = d.stop(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if next.Empty {
		next.Active = true
		return d.saveCheckpoint(next)
	}
	config, err := compiler.CompileOpenVPN(state.Services[0], time.Now().UTC())
	if err != nil {
		return err
	}
	revision := filepath.Join(d.root, "revisions", next.Digest)
	if err = privateDirectory(revision, true); err != nil {
		return err
	}
	ccd := filepath.Join(revision, "ccd")
	if err = privateDirectory(ccd, true); err != nil {
		return err
	}
	for _, c := range state.Services[0].Clients {
		if err = writePrivate(filepath.Join(ccd, "client-"+c.ID), []byte("# Authorized certificate identity.\n")); err != nil {
			return err
		}
	}
	// These commands are fixed trusted local helpers; no API data reaches a shell.
	config = []byte(strings.Replace(string(config), "script-security 1\n", "script-security 2\nclient-connect \""+AgentExecutable+" openvpn-traffic-event\"\nclient-disconnect \""+AgentExecutable+" openvpn-traffic-event\"\n", 1))
	if err = writePrivate(filepath.Join(revision, "server.conf"), config); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(revision, "status.log")); err != nil && !os.IsNotExist(err) {
		return err
	}
	pending := filepath.Join(d.root, ".current")
	if err = os.Remove(pending); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = os.Symlink(revision, pending); err != nil {
		return err
	}
	if err = os.Rename(pending, filepath.Join(d.root, "current")); err != nil {
		return err
	}
	if _, err = unit(ctx, "start", ManagedService); err != nil {
		d.stop()
		return ErrRuntime
	}
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		active, e := unit(ctx, "is-active", ManagedService)
		_, tunErr := net.InterfaceByName("vpnovpn0")
		if e == nil && active == "active" && tunErr == nil {
			next.Active = true
			if err = d.saveCheckpoint(next); err != nil {
				d.stop()
			}
			return err
		}
		select {
		case <-ctx.Done():
			d.stop()
			return ctx.Err()
		case <-timer.C:
			d.stop()
			return ErrRuntime
		case <-ticker.C:
		}
	}
}
func (d *Driver) Health() (bool, error) {
	d.mu.RLock()
	c := d.current
	d.mu.RUnlock()
	if !c.Active {
		return false, ErrRuntime
	}
	if c.Empty {
		return true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	active, err := unit(ctx, "is-active", ManagedService)
	if err != nil || active != "active" {
		return false, ErrRuntime
	}
	_, err = net.InterfaceByName("vpnovpn0")
	return err == nil, err
}
func (d *Driver) CurrentVersion() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.current.Active && !d.current.Empty {
		return model.OpenVPNPinnedVersion
	}
	return ""
}
func (d *Driver) CoreType() string { return "openvpn" }
func (d *Driver) Close() error     { return d.stop() }
func (d *Driver) ConfirmHealthyDesired(ctx context.Context, state model.DesiredState) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	want, err := desiredCheckpoint(state)
	if err != nil {
		return err
	}
	got, err := d.readCheckpoint()
	if err != nil || !got.Active || got.Generation != want.Generation || got.Digest != want.Digest {
		return ErrRuntime
	}
	healthy, err := d.Health()
	if !healthy {
		return ErrRuntime
	}
	return err
}
func (d *Driver) RestoreTerminalAssignment(ctx context.Context, a model.AgentAssignment) error {
	if a.DeploymentStatus != "healthy" || a.FenceRequest != nil || a.NodeAppliedGeneration != a.DesiredState.Generation {
		return ErrRuntime
	}
	want, err := desiredCheckpoint(a.DesiredState)
	if err != nil {
		return err
	}
	version := model.OpenVPNPinnedVersion
	if want.Empty {
		version = ""
	}
	if a.AppliedCoreVersion != version {
		return ErrRuntime
	}
	got, err := d.readCheckpoint()
	if err != nil || !got.Active || got.Generation != want.Generation || got.Digest != want.Digest {
		return ErrRuntime
	}
	d.mu.RLock()
	running := d.current.Active && d.current.Generation == want.Generation && d.current.Digest == want.Digest
	d.mu.RUnlock()
	if running {
		return d.ConfirmHealthyDesired(ctx, a.DesiredState)
	}
	return d.Reconcile(ctx, a.DesiredState)
}
func (d *Driver) Traffic(ctx context.Context) (string, []model.ClientTraffic, error) {
	invocation, err := unit(ctx, "show", ManagedService, "--property=InvocationID", "--value")
	updates := []Session{}
	if err != nil {
		return "", nil, ErrTraffic
	}
	if err == nil && invocationID.MatchString(invocation) {
		raw, e := os.ReadFile(filepath.Join(d.root, "current", "status.log"))
		if e == nil {
			updates, e = parseStatus(raw, invocation)
			if e != nil {
				return "", nil, e
			}
			after, e := unit(ctx, "show", ManagedService, "--property=InvocationID", "--value")
			if e != nil || after != invocation {
				return "", nil, ErrTraffic
			}
		} else if !os.IsNotExist(e) {
			return "", nil, e
		}
	}
	return trafficLedger(ctx, d.root, invocation, "", updates)
}

// Provision is explicit and runs only while the installer owns this node. The
// reviewed OpenVPN package must already have been prepared.
func Provision(ctx context.Context, base string) error {
	if !safePath.MatchString(base) || filepath.Clean(base) != base {
		return ErrRuntime
	}
	if err := verifyBinary(ctx); err != nil {
		return err
	}
	root := filepath.Join(base, "openvpn")
	if err := privateDirectory(root, true); err != nil {
		return err
	}
	if err := privateDirectory(filepath.Join(root, "revisions"), true); err != nil {
		return err
	}
	if err := PrepareNetwork(ctx); err != nil {
		return err
	}
	text := fmt.Sprintf(`[Unit]
Description=VPN Platform OpenVPN
BindsTo=vpn-platform-node-agent.service
After=vpn-platform-node-agent.service network-online.target
[Service]
Type=simple
WorkingDirectory=%s/current
Environment=VPN_PLATFORM_OPENVPN_DATA_DIR=%s
ExecStart=/usr/sbin/openvpn --config server.conf --setenv VPN_PLATFORM_OPENVPN_DATA_DIR %s --setenv VPN_PLATFORM_OPENVPN_INVOCATION ${INVOCATION_ID}
Restart=no
UMask=0077
TimeoutStopSec=12
KillMode=control-group
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=%s
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
`, root, base, base, root)
	path := "/etc/systemd/system/" + ManagedService
	old, err := os.ReadFile(path)
	if err == nil && string(old) != text {
		return ErrRuntime
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err = os.WriteFile(path, []byte(text), 0644); err != nil {
		return err
	}
	networkUnit := "[Unit]\nDescription=VPN Platform OpenVPN tunnel isolation\nBefore=vpn-platform-node-agent.service\n[Service]\nType=oneshot\nRemainAfterExit=true\nExecStart=" + AgentExecutable + " openvpn-network-start\n[Install]\nWantedBy=multi-user.target\n"
	if err = os.WriteFile("/etc/systemd/system/vpn-platform-openvpn-network.service", []byte(networkUnit), 0644); err != nil {
		return err
	}
	dropin := "/etc/systemd/system/vpn-platform-node-agent.service.d"
	if err = os.MkdirAll(dropin, 0755); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dropin, "50-openvpn-network.conf"), []byte("[Unit]\nRequires=vpn-platform-openvpn-network.service\nAfter=vpn-platform-openvpn-network.service\n"), 0644); err != nil {
		return err
	}
	if _, err = unit(ctx, "daemon-reload"); err != nil {
		return err
	}
	_, err = unit(ctx, "enable", "--now", "vpn-platform-openvpn-network.service")
	return err
}
