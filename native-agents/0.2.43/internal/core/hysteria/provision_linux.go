//go:build linux

package hysteria

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"vpn-platform/internal/core"
)

var ErrProvision = errors.New("Hysteria managed service provisioning failed or requires repair")

type unitProvisioner struct {
	directory, unit, owner string
	agentBinary            string // Candidate-only override; production uses the fixed installed agent.
	run                    func(context.Context, ...string) ([]byte, error)
}

// ProvisionManagedRuntime is an explicit Hysteria-only operation. The caller must
// hold the node lifecycle lock and have backed up the unit/agent with a rollback
// guard. It never migrates an existing Xray node or starts the managed core.
// The selected core and managed account persist across failed installation; their
// identities are not recycled while private runtime material may reference them.
func ProvisionManagedRuntime(ctx context.Context, base, agentVersion string) (ManagedIdentity, error) {
	var empty ManagedIdentity
	if ctx.Err() != nil {
		return empty, ctx.Err()
	}
	if _, err := core.ReadRuntimeSelection(base, "hysteria2", agentVersion); err != nil {
		return empty, err
	}
	identity, err := EnsureManagedAccount(ctx)
	if err != nil {
		return empty, err
	}
	if _, err = core.SelectRuntimeCore(ctx, base, "hysteria2", agentVersion); err != nil {
		return empty, err
	}
	if err = prepareManagedBase(base, identity); err != nil {
		return empty, err
	}
	installer := unitProvisioner{directory: "/etc/systemd/system", unit: ManagedService, owner: ManagedAgentService, run: func(ctx context.Context, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "systemctl", args...).Output()
	}}
	if err = installer.ensure(ctx, base, identity); err != nil {
		return empty, err
	}
	return identity, nil
}

// The node installer may have created DATA with umask 077. Allow the exclusive
// core group to traverse DATA, while preserving all private child modes. Unlike
// a recursive chmod/chown, this does not grant access to agent tokens or ACME keys.
func prepareManagedBase(base string, identity ManagedIdentity) error {
	if !validRuntimeIdentity(identity.UID, identity.GID) {
		return ErrProvision
	}
	if err := runtimeTLSDirectory(base, identity.GID); err != nil {
		return ErrProvision
	}
	return nil
}

func (p unitProvisioner) ensure(ctx context.Context, base string, identity ManagedIdentity) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !managedUnitName.MatchString(p.unit) || !managedAgentUnitName.MatchString(p.owner) || !filepath.IsAbs(p.directory) || protectedDirectory(p.directory, false) != nil || p.run == nil {
		return ErrProvision
	}
	binary := p.agentBinary
	if binary == "" {
		binary = "/usr/local/bin/vpn-node-agent"
	}
	if p.agentBinary != "" && (p.unit == ManagedService || p.owner == ManagedAgentService) {
		return ErrProvision
	}
	expected, err := renderManagedUnitWithAgent(base, identity.UID, identity.GID, p.owner, binary)
	if err != nil {
		return err
	}
	path := filepath.Join(p.directory, p.unit)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || !ownedBy(info, 0, -1) || info.Size() > 16<<10 {
			return ErrProvision
		}
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, expected) {
			return ErrProvision
		}
	} else if !os.IsNotExist(err) {
		return ErrProvision
	} else {
		file, err := os.CreateTemp(p.directory, ".hysteria-unit-")
		if err != nil {
			return ErrProvision
		}
		defer os.Remove(file.Name())
		_, writeErr := file.Write(expected)
		modeErr := file.Chmod(0644)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || modeErr != nil || syncErr != nil || closeErr != nil || ctx.Err() != nil {
			return ErrProvision
		}
		if err = os.Link(file.Name(), path); err != nil {
			// A concurrent publisher must be inspected by a retry, never overwritten.
			return ErrProvision
		}
		if syncDirectory(p.directory) != nil {
			return ErrProvision
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Reload also repairs a crash after publication but before daemon-reload. It
	// does not restart a healthy existing invocation. V1 refuses template drift;
	// future template upgrades need an explicit reviewed migration under the guard.
	if _, err = p.run(ctx, "daemon-reload"); err != nil {
		return ErrProvision
	}
	return p.verifyLoaded(ctx, path)
}

func (p unitProvisioner) verifyLoaded(ctx context.Context, path string) error {
	raw, err := p.run(ctx, "show", p.unit, "--property=FragmentPath,DropInPaths,NeedDaemonReload", "--no-pager")
	if err != nil || len(raw) > 8192 {
		return ErrProvision
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return ErrProvision
		}
		if _, exists := values[key]; exists {
			return ErrProvision
		}
		values[key] = value
	}
	if len(values) != 3 || values["FragmentPath"] != path || values["DropInPaths"] != "" || values["NeedDaemonReload"] != "no" {
		return ErrProvision
	}
	return nil
}

// VerifyManagedRuntime is read-only: require the exact reviewed unit, root
// ownership and no loaded drop-ins, without daemon-reload, chmod or replacement.
func VerifyManagedRuntime(ctx context.Context, base string, identity ManagedIdentity) error {
	p := unitProvisioner{directory: "/etc/systemd/system", unit: ManagedService, owner: ManagedAgentService, run: func(ctx context.Context, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "systemctl", args...).Output()
	}}
	return p.verify(ctx, base, identity)
}
func (p unitProvisioner) verify(ctx context.Context, base string, identity ManagedIdentity) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !managedUnitName.MatchString(p.unit) || !managedAgentUnitName.MatchString(p.owner) || protectedDirectory(p.directory, false) != nil || p.run == nil {
		return ErrProvision
	}
	binary := p.agentBinary
	if binary == "" {
		binary = "/usr/local/bin/vpn-node-agent"
	}
	if p.agentBinary != "" && (p.unit == ManagedService || p.owner == ManagedAgentService) {
		return ErrProvision
	}
	expected, err := renderManagedUnitWithAgent(base, identity.UID, identity.GID, p.owner, binary)
	if err != nil {
		return ErrProvision
	}
	path := filepath.Join(p.directory, p.unit)
	current, err := readTLSFile(path, 16<<10, 0644, -1)
	if err != nil || !bytes.Equal(current, expected) {
		return ErrProvision
	}
	return p.verifyLoaded(ctx, path)
}
