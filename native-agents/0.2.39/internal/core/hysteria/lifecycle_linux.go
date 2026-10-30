//go:build linux

package hysteria

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// OpenManagedDriver requires exclusive node-agent ownership and a preinstalled,
// verified managed unit/account. It does not install a unit or select a core for
// a node. The caller must Close before releasing that ownership. Existing Xray
// nodes must never enter this lifecycle implicitly.
//
// A new lifetime first confirms the old invocation stopped. It then reuses the
// private settings/checkpoints, owns the local authorization endpoint and recovers
// the runtime. Damaged state fails closed; no applied deployment is inferred here.
func OpenManagedDriver(ctx context.Context, base string, uid, gid int, unit string, beforeStop func(context.Context)) (*Driver, error) {
	return openManagedDriver(ctx, base, uid, gid, unit, beforeStop, true)
}

// OpenPendingManagedDriver establishes local ownership but leaves the core
// stopped until an authoritative healthy assignment or a new execution lease
// authorizes recovery. It is the normal agent-startup entry point.
func OpenPendingManagedDriver(ctx context.Context, base string, uid, gid int, unit string, beforeStop func(context.Context)) (*Driver, error) {
	return openManagedDriver(ctx, base, uid, gid, unit, beforeStop, false)
}
func openManagedDriver(ctx context.Context, base string, uid, gid int, unit string, beforeStop func(context.Context), recover bool) (*Driver, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !validRuntimeIdentity(uid, gid) || !managedUnitName.MatchString(unit) {
		return nil, ErrDriver
	}
	installer, err := NewInstaller(base)
	if err != nil {
		return nil, err
	}
	// Stop does not call the statistics endpoint. A temporary adapter permits
	// quiescence even when the settings needed for real statistics are damaged.
	unusedStatistics, err := NewStatistics(1024, strings.Repeat("0", 32))
	if err != nil {
		return nil, err
	}
	system, err := NewSystemdRuntime(unit, unusedStatistics)
	if err != nil {
		return nil, err
	}
	if beforeStop != nil {
		capture, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		beforeStop(capture)
		cancel()
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = system.Stop(cleanup)
	cancel()
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	settings, err := openRuntimeSettings(base, uid, gid)
	if err != nil {
		return nil, err
	}
	statistics, err := NewStatistics(settings.StatisticsPort, settings.StatisticsSecret)
	if err != nil {
		return nil, err
	}
	system.statistics = statistics
	certificates, err := NewCertificateRuntime(base, gid)
	if err != nil {
		return nil, err
	}
	store, err := newRevisionStore(installer, certificates, settings.options())
	if err != nil {
		return nil, err
	}
	transaction, err := newRuntimeTransaction(store, system, filepath.Join(store.root(), "control", "access.json"), beforeStop)
	if err != nil {
		return nil, err
	}
	driver, err := newDriver(transaction, uid, gid)
	if err != nil {
		return nil, err
	}
	authorization, err := StartAuthorizationServer(settings.AuthPort, transaction.access)
	if err != nil {
		return nil, err
	}
	driver.authorization = authorization
	driver.system = system
	if recover {
		if err = driver.Recover(ctx); err != nil {
			return nil, errors.Join(err, driver.Close())
		}
	}
	return driver, nil
}

// Close permanently fences the lifetime, stops its core and releases its local
// listener. Shutdown alone fences/stops but leaves listener ownership to Close.
func (d *Driver) Close() error {
	if d.authorization != nil {
		return d.authorization.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	return d.Shutdown(ctx)
}

// The same invocation source and authenticated statistics adapter are provided
// to the agent's durable traffic collector, preventing mixed restart epochs.
func (d *Driver) Invocation(ctx context.Context) (string, error) {
	if d.system == nil {
		return "", ErrSystemdRuntime
	}
	return d.system.Invocation(ctx)
}
func (d *Driver) Statistics() *Statistics {
	if d.system == nil {
		return nil
	}
	return d.system.statistics
}
