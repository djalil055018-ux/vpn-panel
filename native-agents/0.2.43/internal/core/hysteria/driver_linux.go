//go:build linux

package hysteria

import (
	"context"
	"errors"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

var ErrDriver = errors.New("Hysteria managed runtime did not converge")

// Driver coordinates staged artifacts, immutable certificate material, native
// preflight and access-preserving rollback. Provisioning and authorization-server
// ownership are deliberately required from the outer agent lifecycle; this
// driver is not yet selected by the production agent.
type Driver struct {
	authorization *AuthorizationServer
	system        *SystemdRuntime
	transaction   *runtimeTransaction
	uid, gid      int
	gate          chan struct{}
	validate      func(context.Context, model.DesiredState, int, int) error
	fence         desiredFence
}

func newDriver(transaction *runtimeTransaction, uid, gid int) (*Driver, error) {
	if transaction == nil || !validRuntimeIdentity(uid, gid) || transaction.store.certificates.gid != gid {
		return nil, ErrDriver
	}
	fence := desiredFence{path: transaction.access.policy.persistent.path + ".desired"}
	minimum, _ := transaction.access.policy.PendingRevocations()
	if _, err := fence.read(minimum); err != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		return nil, errors.Join(err, transaction.access.Shutdown(ctx))
	}
	return &Driver{transaction: transaction, uid: uid, gid: gid, gate: make(chan struct{}, 1), validate: transaction.store.installer.Validate, fence: fence}, nil
}
func (d *Driver) lock(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case d.gate <- struct{}{}:
	}
	if ctx.Err() != nil {
		<-d.gate
		return ctx.Err()
	}
	return nil
}

func (d *Driver) prepare(ctx context.Context, state model.DesiredState) (*runtimeRevision, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	store := d.transaction.store
	if state.Core.Type != "hysteria2" || len(state.Services) > 1 {
		return nil, ErrDriver
	}
	state.Services = append([]model.ServiceSpec(nil), state.Services...)
	for index := range state.Services {
		service := &state.Services[index]
		if service.TLS == nil {
			return nil, ErrTLSMaterial
		}
		resolved, err := store.certificates.Stage(*service.TLS)
		if err != nil {
			return nil, err
		}
		service.TLS = &resolved
	}
	if _, err := compiler.CompileHysteria(state, store.options); err != nil {
		return nil, err
	}
	if _, err := store.installer.Install(ctx, state.Core); err != nil {
		return nil, err
	}
	revision, err := store.stage(ctx, state)
	if err != nil {
		return nil, err
	}
	if err = d.validate(ctx, state, d.uid, d.gid); err != nil {
		return nil, err
	}
	return revision, nil
}

func (d *Driver) Reconcile(ctx context.Context, state model.DesiredState) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	if d.transaction.access.closed.Load() {
		return ErrDriver
	}
	if state.Generation <= 0 {
		return ErrAccessJournal
	}
	if state.Core.Type != "hysteria2" || len(state.Services) > 1 {
		return ErrDriver
	}
	clients := clientsForState(state)
	if _, err := buildSnapshot(clients); err != nil {
		return err
	}
	minimum, _ := d.transaction.access.policy.PendingRevocations()
	if err := d.fence.check(state, minimum); err != nil {
		return err
	}
	revision, err := d.prepare(ctx, state)
	if err != nil {
		return err
	}
	if d.transaction.access.closed.Load() {
		return ErrDriver
	}
	if err = d.fence.commit(ctx, state, minimum); err != nil {
		return err
	}
	return d.transaction.applyPrepared(ctx, revision, state.Generation, clients)
}

// Recover requires a live execution lease and a serving local authorization
// endpoint. A missing policy stays stopped; a missing/corrupt runtime with a
// policy fails closed. It never infers an applied deployment generation.
func (d *Driver) Recover(ctx context.Context) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	if err := d.transaction.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.transaction.gate }()
	minimum, _ := d.transaction.access.policy.PendingRevocations()
	if _, err := d.fence.read(minimum); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		return errors.Join(err, d.transaction.access.Shutdown(cleanup))
	}
	return d.transaction.access.Recover(ctx)
}

func (d *Driver) RefreshTLSCertificateContext(ctx context.Context, id, domain string) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer func() { <-d.gate }()
	if d.transaction.access.closed.Load() {
		return ErrDriver
	}
	minimum, _ := d.transaction.access.policy.PendingRevocations()
	if _, err := d.fence.read(minimum); err != nil {
		return err
	}
	current, err := d.transaction.store.current(ctx)
	if err != nil {
		return err
	}
	if current == nil || current.idle() {
		return nil
	}
	spec := current.state.Services[0].TLS
	if spec.CertificateID != id {
		return nil
	}
	if spec.ServerName != domain {
		return ErrTLSMaterial
	}
	candidate, err := d.prepare(ctx, current.state)
	if err != nil {
		return err
	}
	return d.transaction.refreshPrepared(ctx, candidate)
}

func (d *Driver) HealthContext(ctx context.Context) (bool, error) {
	if err := d.lock(ctx); err != nil {
		return false, err
	}
	defer func() { <-d.gate }()
	if d.transaction.access.closed.Load() {
		return false, ErrDriver
	}
	minimum, _ := d.transaction.access.policy.PendingRevocations()
	if _, err := d.fence.read(minimum); err != nil {
		return false, err
	}
	current, err := d.transaction.store.current(ctx)
	if err != nil || current == nil {
		return false, ErrRuntimeRevision
	}
	if _, err = d.transaction.store.load(ctx, current.id, true); err != nil {
		return false, err
	}
	if err = d.transaction.runtime.Ready(ctx); err != nil {
		return false, err
	}
	return true, nil
}
func (d *Driver) Health() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.HealthContext(ctx)
}
func (d *Driver) CoreType() string { return "hysteria2" }

func (d *Driver) CurrentVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.lock(ctx); err != nil {
		return ""
	}
	defer func() { <-d.gate }()
	current, err := d.transaction.store.current(ctx)
	if err != nil || current == nil || current.idle() {
		return ""
	}
	return current.state.Core.Version
}
func (d *Driver) Shutdown(ctx context.Context) error { return d.transaction.access.Shutdown(ctx) }
