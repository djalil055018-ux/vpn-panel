//go:build linux

package pptp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

const ManagedService = "vpn-platform-pptp.service"
const AgentExecutable = "/usr/local/bin/vpn-node-agent"

var safePath = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

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

func unit(ctx context.Context, args ...string) (string, error) {
	raw, err := exec.CommandContext(ctx, "systemctl", args...).Output()
	return strings.TrimSpace(string(raw)), err
}
func Open(ctx context.Context, base string) (*Driver, error) {
	root := filepath.Join(base, "pptp")
	if err := privateDirectory(root, false); err != nil {
		return nil, err
	}
	if err := VerifyArtifact(ctx); err != nil {
		return nil, err
	}
	if err := VerifyNetwork(ctx); err != nil {
		return nil, err
	}
	if _, _, err := trafficLedger(ctx, root, "", "read", nil); err != nil {
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
	raw, e := readPrivate(filepath.Join(d.root, "checkpoint.json"), 4096)
	if e != nil {
		return c, e
	}
	if json.Unmarshal(raw, &c) != nil || c.Generation <= 0 || !digestPattern.MatchString(c.Digest) {
		return c, ErrRuntime
	}
	return c, nil
}
func (d *Driver) saveCheckpoint(c checkpoint) error {
	raw, e := json.Marshal(c)
	if e == nil {
		e = writePrivate(filepath.Join(d.root, "checkpoint.json"), raw)
	}
	if e == nil {
		d.mu.Lock()
		d.current = c
		d.mu.Unlock()
	}
	return e
}
func desiredCheckpoint(state model.DesiredState) (checkpoint, error) {
	if state.Generation <= 0 || state.Core.Type != "pptp" || state.Core.Version != model.PPTPPinnedVersion || state.Core.SHA256 != model.PPTPPinnedSHA256 || state.Core.DownloadURL != model.PPTPPinnedDownloadURL || len(state.Services) > 1 {
		return checkpoint{}, ErrRuntime
	}
	for _, s := range state.Services {
		if e := compiler.ValidatePPTPService(s); e != nil {
			return checkpoint{}, e
		}
	}
	raw, e := json.Marshal(state)
	if e != nil {
		return checkpoint{}, e
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if d.BeforeStop != nil {
		d.BeforeStop(ctx)
	}
	_, e := unit(ctx, "stop", ManagedService)
	if d.BeforeStop != nil {
		d.BeforeStop(ctx)
	}
	return e
}
func (d *Driver) failClosed() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	unit(ctx, "stop", ManagedService)
}

// Persist the generation fence before stopping access. There is no fallback to
// a prior allowlist after any partial new-generation apply.
func (d *Driver) Reconcile(ctx context.Context, state model.DesiredState) error {
	if e := d.lock(ctx); e != nil {
		return e
	}
	defer func() { <-d.gate }()
	next, e := desiredCheckpoint(state)
	if e != nil {
		return e
	}
	prior, e := d.readCheckpoint()
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if next.Generation < prior.Generation || (next.Generation == prior.Generation && next.Digest != prior.Digest) {
		return ErrRuntime
	}
	next.Active = prior.Active && prior.Generation == next.Generation && prior.Digest == next.Digest
	if e = VerifyArtifact(ctx); e != nil {
		return e
	}
	if e = VerifyNetwork(ctx); e != nil {
		return e
	}
	if e = d.saveCheckpoint(next); e != nil {
		return e
	}
	if e = d.stop(); e != nil {
		return e
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if next.Empty {
		next.Active = true
		return d.saveCheckpoint(next)
	}
	secret, e := readPrivate(filepath.Join(d.root, "cli-password"), 128)
	if e != nil {
		return e
	}
	config, secrets, e := compiler.CompilePPTP(state.Services[0], string(secret))
	if e != nil {
		return e
	}
	revision := filepath.Join(d.root, "revisions", next.Digest)
	if e = privateDirectory(revision, true); e != nil {
		return e
	}
	for name, data := range map[string][]byte{"accel-ppp.conf": config, "chap-secrets": secrets} {
		if e = writePrivate(filepath.Join(revision, name), data); e != nil {
			return e
		}
	}
	for name, event := range map[string]string{"ip-pre-up": "start", "ip-down": "finish"} {
		script := fmt.Sprintf("#!/bin/sh\nexec %s pptp-traffic-event %s %s %s\n", AgentExecutable, d.root, next.Digest, event)
		path := filepath.Join(revision, name)
		if e = writePrivate(path, []byte(script)); e != nil {
			return e
		}
		if e = os.Chmod(path, 0700); e != nil {
			return e
		}
	}
	pending := filepath.Join(d.root, ".current")
	if e = os.Remove(pending); e != nil && !os.IsNotExist(e) {
		return e
	}
	if e = os.Symlink(revision, pending); e != nil {
		return e
	}
	if e = os.Rename(pending, filepath.Join(d.root, "current")); e != nil {
		return e
	}
	if _, e = unit(ctx, "start", ManagedService); e != nil {
		d.failClosed()
		return ErrRuntime
	}
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if e = d.runtimeHealth(ctx); e == nil {
			next.Active = true
			if e = d.saveCheckpoint(next); e != nil {
				d.failClosed()
			}
			return e
		}
		select {
		case <-ctx.Done():
			d.failClosed()
			return ctx.Err()
		case <-timer.C:
			d.failClosed()
			return ErrRuntime
		case <-ticker.C:
		}
	}
}
func (d *Driver) runtimeHealth(ctx context.Context) error {
	if e := VerifyNetwork(ctx); e != nil {
		return e
	}
	active, e := unit(ctx, "is-active", ManagedService)
	if e != nil || active != "active" {
		return ErrRuntime
	}
	raw, e := control(ctx, d.root, "show stat")
	if e != nil || !strings.Contains(string(raw), "pptp:") {
		return ErrRuntime
	}
	if _, _, e = trafficLedger(ctx, d.root, "", "read", nil); e != nil {
		return e
	}
	return nil
}
func (d *Driver) Health() (bool, error) {
	d.mu.RLock()
	c := d.current
	d.mu.RUnlock()
	if !c.Active {
		return false, ErrRuntime
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if c.Empty {
		active, _ := unit(ctx, "is-active", ManagedService)
		return active != "active", nil
	}
	e := d.runtimeHealth(ctx)
	if e != nil {
		d.failClosed()
	}
	return e == nil, e
}
func (d *Driver) CurrentVersion() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.current.Active && !d.current.Empty {
		return model.PPTPPinnedVersion
	}
	return ""
}
func (d *Driver) CoreType() string { return "pptp" }
func (d *Driver) Close() error     { return d.stop() }
func (d *Driver) ConfirmHealthyDesired(ctx context.Context, state model.DesiredState) error {
	if e := d.lock(ctx); e != nil {
		return e
	}
	defer func() { <-d.gate }()
	want, e := desiredCheckpoint(state)
	if e != nil {
		return e
	}
	got, e := d.readCheckpoint()
	if e != nil || !got.Active || got.Generation != want.Generation || got.Digest != want.Digest {
		return ErrRuntime
	}
	healthy, e := d.Health()
	if !healthy {
		return ErrRuntime
	}
	return e
}
func (d *Driver) RestoreTerminalAssignment(ctx context.Context, a model.AgentAssignment) error {
	if a.DeploymentStatus != "healthy" || a.FenceRequest != nil || a.NodeAppliedGeneration != a.DesiredState.Generation {
		return ErrRuntime
	}
	want, e := desiredCheckpoint(a.DesiredState)
	if e != nil {
		return e
	}
	version := model.PPTPPinnedVersion
	if want.Empty {
		version = ""
	}
	if a.AppliedCoreVersion != version {
		return ErrRuntime
	}
	got, e := d.readCheckpoint()
	if e != nil || !got.Active || got.Generation != want.Generation || got.Digest != want.Digest {
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
	active, e := unit(ctx, "is-active", ManagedService)
	if e != nil || active != "active" {
		return trafficLedger(ctx, d.root, "", "read", nil)
	}
	invocation, e := unit(ctx, "show", ManagedService, "--property=InvocationID", "--value")
	if e != nil || !invocationPattern.MatchString(invocation) {
		d.failClosed()
		return "", nil, ErrTraffic
	}
	raw, e := control(ctx, d.root, "show sessions sid,username,rx-bytes-raw,tx-bytes-raw,state,ifname")
	if e != nil {
		d.failClosed()
		return "", nil, ErrTraffic
	}
	sessions, e := parseSessions(raw)
	if e != nil {
		d.failClosed()
		return "", nil, e
	}
	after, e := unit(ctx, "show", ManagedService, "--property=InvocationID", "--value")
	if e != nil || after != invocation {
		return "", nil, ErrTraffic
	}
	epoch, clients, e := trafficLedger(ctx, d.root, invocation, "sample", sessions)
	if e != nil {
		d.failClosed()
	}
	return epoch, clients, e
}

// Runs as systemd's main process, records its invocation before accepting any
// client, then execs the pinned daemon. It does not acquire the Agent's lock.
func StartRuntime(ctx context.Context, base string) error {
	if e := VerifyArtifact(ctx); e != nil {
		return e
	}
	if e := VerifyNetwork(ctx); e != nil {
		return e
	}
	root := filepath.Join(base, "pptp")
	if e := privateDirectory(root, false); e != nil {
		return e
	}
	d := &Driver{root: root}
	c, e := d.readCheckpoint()
	if e != nil || c.Empty {
		return ErrRuntime
	}
	current, e := os.Readlink(filepath.Join(root, "current"))
	expected := filepath.Join(root, "revisions", c.Digest)
	if e != nil || current != expected {
		return ErrRuntime
	}
	if e = privateDirectory(current, false); e != nil {
		return e
	}
	invocation := os.Getenv("INVOCATION_ID")
	if !invocationPattern.MatchString(invocation) {
		return ErrRuntime
	}
	if _, _, e = trafficLedger(ctx, root, invocation, "begin", nil); e != nil {
		return e
	}
	if e = writePrivate(filepath.Join(current, "invocation"), []byte(invocation)); e != nil {
		return e
	}
	if e = os.Chdir(current); e != nil {
		return e
	}
	return syscall.Exec(runtimeBinary, []string{runtimeBinary, "-c", "accel-ppp.conf", "-p", "accel.pid"}, os.Environ())
}

func managedFile(path, text string) error {
	info, e := os.Lstat(path)
	if e == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || (info.Mode().Perm() != 0644 && info.Mode().Perm() != 0600) {
			return ErrRuntime
		}
		old, e := os.ReadFile(path)
		if e != nil || string(old) != text {
			return ErrRuntime
		}
		// A restrictive caller umask must not make a matching managed unit
		// impossible to repair. Only the exact public unit text is normalized.
		return os.Chmod(path, 0644)
	}
	if !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".pptp-unit-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.WriteString(text); e != nil {
		f.Close()
		return e
	}
	if e = f.Chmod(0644); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func Provision(ctx context.Context, base string) error {
	if !safePath.MatchString(base) || filepath.Clean(base) != base {
		return ErrRuntime
	}
	if e := VerifyArtifact(ctx); e != nil {
		return e
	}
	root := filepath.Join(base, "pptp")
	if e := privateDirectory(root, true); e != nil {
		return e
	}
	if e := privateDirectory(filepath.Join(root, "revisions"), true); e != nil {
		return e
	}
	if _, e := os.Stat(filepath.Join(root, "checkpoint.json")); e == nil {
		if _, _, e = trafficLedger(ctx, root, "", "read", nil); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if _, _, e := trafficLedger(ctx, root, "", "initialize", nil); e != nil {
		return e
	}
	secretPath := filepath.Join(root, "cli-password")
	raw, e := readPrivate(secretPath, 128)
	if os.IsNotExist(e) {
		b := make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			return e
		}
		raw = []byte(hex.EncodeToString(b))
		if e = writePrivate(secretPath, raw); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if !digestPattern.Match(raw) {
		return ErrRuntime
	}
	if e = PrepareNetwork(ctx); e != nil {
		return e
	}
	text := fmt.Sprintf(`[Unit]
Description=VPN Platform PPTP legacy compatibility
BindsTo=vpn-platform-node-agent.service
After=vpn-platform-node-agent.service network-online.target
[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s pptp-runtime-start %s
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
DevicePolicy=closed
DeviceAllow=/dev/ppp rw
`, root, AgentExecutable, base, root)
	if e = managedFile("/etc/systemd/system/"+ManagedService, text); e != nil {
		return e
	}
	networkUnit := "[Unit]\nDescription=VPN Platform PPTP tunnel isolation\nBefore=vpn-platform-node-agent.service\n[Service]\nType=oneshot\nRemainAfterExit=true\nExecStart=" + AgentExecutable + " pptp-network-start\n[Install]\nWantedBy=multi-user.target\n"
	if e = managedFile("/etc/systemd/system/vpn-platform-pptp-network.service", networkUnit); e != nil {
		return e
	}
	dropin := "/etc/systemd/system/vpn-platform-node-agent.service.d"
	if e = os.MkdirAll(dropin, 0755); e != nil {
		return e
	}
	if e = managedFile(filepath.Join(dropin, "70-pptp-network.conf"), "[Unit]\nRequires=vpn-platform-pptp-network.service\nAfter=vpn-platform-pptp-network.service\n"); e != nil {
		return e
	}
	if _, e = unit(ctx, "daemon-reload"); e != nil {
		return e
	}
	_, e = unit(ctx, "enable", "--now", "vpn-platform-pptp-network.service")
	return e
}
