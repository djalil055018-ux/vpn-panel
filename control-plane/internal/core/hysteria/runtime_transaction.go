package hysteria

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"vpn-platform/internal/model"
)

type managedCore interface {
	AccessRuntime
	Stopped(context.Context) error
}

// revisionRuntime is only used behind AccessManager. Structural changes stop
// the old invocation before switching the immutable revision pointer. Access-only
// additions retain the invocation; revoked credentials still force AccessManager's
// full stop even when the compiled runtime revision remains unchanged.
type revisionRuntime struct {
	store            *revisionStore
	system           managedCore
	beforeStop       func(context.Context)
	mu               sync.Mutex
	pending          *runtimeRevision
	mutated, stopped bool
	mode             atomic.Int32 // 0 unknown/stopped; 1 intentional idle; 2 running candidate
}

func (r *revisionRuntime) prepare(revision *runtimeRevision) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = revision
	r.mutated = false
}
func (r *revisionRuntime) finish() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = nil
	return r.mutated
}
func (r *revisionRuntime) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mutated = true
	r.mode.Store(0)
	err := r.system.Stop(ctx)
	r.stopped = err == nil
	return err
}
func (r *revisionRuntime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, err := r.store.current(ctx)
	if err != nil {
		return err
	}
	selected := r.pending
	if selected == nil {
		selected = current
	}
	if selected == nil {
		return ErrRuntimeRevision
	}
	changed := current == nil || selected.id != current.id
	if changed || selected.idle() {
		r.mutated = true
		r.mode.Store(0)
		if !r.stopped {
			if r.beforeStop != nil {
				captureCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				r.beforeStop(captureCtx)
				cancel()
			}
			if err = r.system.Stop(ctx); err != nil {
				return err
			}
			r.stopped = true
		}
		if changed {
			if err = r.store.activate(ctx, selected.id); err != nil {
				return err
			}
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if selected.idle() {
		r.mode.Store(1)
		return nil
	}
	r.mutated = true
	r.stopped = false
	if err = r.system.Start(ctx); err != nil {
		r.mode.Store(0)
		return err
	}
	r.mode.Store(2)
	return nil
}
func (r *revisionRuntime) Ready(ctx context.Context) error {
	switch r.mode.Load() {
	case 1:
		return r.system.Stopped(ctx)
	case 2:
		return r.system.Ready(ctx)
	default:
		return ErrAccessRuntime
	}
}

type runtimeTransaction struct {
	store   *revisionStore
	runtime *revisionRuntime
	access  *AccessManager
	gate    chan struct{}
}

func newRuntimeTransaction(store *revisionStore, system managedCore, accessPath string, beforeStop func(context.Context)) (*runtimeTransaction, error) {
	if store == nil || system == nil {
		return nil, ErrAccessRuntime
	}
	runtime := &revisionRuntime{store: store, system: system, beforeStop: beforeStop}
	access, err := NewAccessManager(accessPath, runtime, beforeStop)
	if err != nil {
		return nil, err
	}
	return &runtimeTransaction{store: store, runtime: runtime, access: access, gate: make(chan struct{}, 1)}, nil
}

func (t *runtimeTransaction) lock(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case t.gate <- struct{}{}:
	}
	if ctx.Err() != nil {
		<-t.gate
		return ctx.Err()
	}
	return nil
}

// applyPrepared is called only after the full candidate has passed native
// preflight. Its snapshot and pending pointer are serialized with certificate
// refresh and startup recovery. Durable authorization is never rolled back.
func (t *runtimeTransaction) applyPrepared(ctx context.Context, revision *runtimeRevision, generation int64, clients []Client) error {
	if err := t.lock(ctx); err != nil {
		return err
	}
	defer func() { <-t.gate }()
	return t.runPrepared(ctx, revision, func() error { return t.access.Apply(ctx, generation, clients) })
}

// refreshPrepared changes only runtime material. The hash-only authorization
// checkpoint cannot reconstruct credentials and must never be replaced with the
// sanitized revision's empty Clients list during certificate renewal.
func (t *runtimeTransaction) refreshPrepared(ctx context.Context, revision *runtimeRevision) error {
	if err := t.lock(ctx); err != nil {
		return err
	}
	defer func() { <-t.gate }()
	generation, _ := t.access.policy.PendingRevocations()
	if generation == 0 {
		return ErrAccessJournal
	}
	return t.runPrepared(ctx, revision, func() error { return t.access.Recover(ctx) })
}

func (t *runtimeTransaction) runPrepared(ctx context.Context, revision *runtimeRevision, apply func() error) error {
	if t.access.closed.Load() {
		return ErrAccessRuntime
	}
	previous, err := t.store.current(ctx)
	if err != nil {
		return err
	}
	if revision == nil {
		return ErrRuntimeRevision
	}
	if _, err = t.store.load(ctx, revision.id, true); err != nil {
		return err
	}
	t.runtime.prepare(revision)
	err = apply()
	mutated := t.runtime.finish()
	if err == nil {
		return nil
	}
	if !mutated {
		return err
	}
	// AccessManager has already attempted to stop the failed candidate. Confirm
	// stop again before restoring a pointer; never use an expired lease context
	// for cleanup. Recovery must finish before the caller acknowledges its fence.
	recovery, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if stopErr := t.runtime.Stop(recovery); stopErr != nil {
		return errors.Join(err, ErrRuntimeStop)
	}
	if restoreErr := t.store.restore(recovery, previous); restoreErr != nil {
		return errors.Join(err, ErrRuntimeRevision)
	}
	if previous == nil || t.access.closed.Load() || ctx.Err() != nil {
		return err
	}
	// The old core config now uses the NEW durable policy. Removed credentials
	// remain denied. A closed authorization server permanently forbids recovery.
	if recoveryErr := t.access.Recover(recovery); recoveryErr != nil {
		return errors.Join(err, recoveryErr)
	}
	return err
}

func clientsForState(state model.DesiredState) []Client {
	var clients []Client
	for _, service := range state.Services {
		for _, client := range service.Clients {
			clients = append(clients, Client{ID: client.StatsKey, Credential: client.ID})
		}
	}
	return clients
}
