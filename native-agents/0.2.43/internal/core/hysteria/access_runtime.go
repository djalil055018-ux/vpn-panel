package hysteria

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"time"
)

var ErrAccessRuntime = errors.New("Hysteria access runtime did not converge")
var ErrRuntimeStop = errors.New("Hysteria runtime stop could not be confirmed")

// AccessRuntime controls one managed core. Stop must return nil only after all
// processes/connections of the old invocation are gone and automatic restart is
// inhibited. A /kick acknowledgement does NOT satisfy this contract: upstream
// 2.12.2 consumes one kick marker on the first traffic event for that identity.
// Start is idempotent and Ready verifies both the process and its management API.
type AccessRuntime interface {
	Stop(context.Context) error
	Start(context.Context) error
	Ready(context.Context) error
}

// AccessManager owns the authorization checkpoint and serializes lifecycle work.
// Every new manager first quiesces the old core before accepting its state as
// reconciled. Lost agent memory or an interrupted revoke therefore cannot make
// an old connection survive recovery. Structural config/binary/TLS changes must
// be coordinated by the outer driver; this component only reconciles access.
type AccessManager struct {
	policy         *Authorizer
	runtime        AccessRuntime
	beforeStop     func(context.Context)
	gate           chan struct{}
	synchronized   bool
	cleanupTimeout time.Duration
	closed         atomic.Bool
}

func NewAccessManager(path string, runtime AccessRuntime, beforeStop func(context.Context)) (*AccessManager, error) {
	if runtime == nil || !filepath.IsAbs(path) {
		return nil, ErrAccessRuntime
	}
	m := &AccessManager{runtime: runtime, beforeStop: beforeStop,
		gate: make(chan struct{}, 1), cleanupTimeout: 30 * time.Second}
	policy, err := OpenPersistentAuthorizer(path)
	if err != nil {
		return nil, m.failed(err)
	}
	m.policy = policy
	return m, nil
}

func (m *AccessManager) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.policy.ServeHTTP(w, r) }

func (m *AccessManager) lock(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-m.gate
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stop uses an independent, bounded cleanup context: cancellation of a lease
// must not leave a start job or an incompletely revoked connection running.
// Runtime implementations and beforeStop must honor their context deadlines.
func (m *AccessManager) stop() error {
	m.synchronized = false
	if m.beforeStop != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		m.beforeStop(ctx)
		cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.cleanupTimeout)
	defer cancel()
	if m.runtime.Stop(ctx) != nil {
		return ErrRuntimeStop
	}
	return nil
}

func (m *AccessManager) failed(cause error) error {
	if err := m.stop(); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (m *AccessManager) interrupted(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.closed.Load() {
		return ErrAccessRuntime
	}
	return nil
}

func (m *AccessManager) settle(ctx context.Context) error {
	generation, pending := m.policy.PendingRevocations()
	if !m.synchronized || len(pending) != 0 || generation == 0 {
		if err := m.stop(); err != nil {
			return err
		}
		if generation > 0 {
			if err := m.policy.AcknowledgeStoppedRuntime(generation); err != nil {
				return err
			}
		}
	}
	if err := m.interrupted(ctx); err != nil {
		return m.failed(err)
	}
	// Missing checkpoint is deny-all and stays stopped until a valid desired
	// generation arrives. Do not revive a leftover runtime config on startup.
	if generation == 0 {
		return nil
	}
	if err := m.runtime.Start(ctx); err != nil {
		return m.failed(ErrAccessRuntime)
	}
	if err := m.interrupted(ctx); err != nil {
		return m.failed(err)
	}
	if err := m.runtime.Ready(ctx); err != nil {
		return m.failed(ErrAccessRuntime)
	}
	if err := m.interrupted(ctx); err != nil {
		return m.failed(err)
	}
	m.synchronized = true
	return nil
}

// Apply persists the new policy before revoking sessions. Any removed or rotated
// credential requires a full core stop, durable acknowledgement, and restart.
// Additions alone need no restart after initial synchronization. A failure never
// rolls back to credentials that the new durable policy has already revoked.
func (m *AccessManager) Apply(ctx context.Context, generation int64, clients []Client) error {
	if _, err := buildSnapshot(clients); err != nil {
		return err
	}
	if generation <= 0 {
		return ErrAccessJournal
	}
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer func() { <-m.gate }()
	if m.closed.Load() {
		return ErrAccessRuntime
	}
	if _, err := m.policy.Commit(generation, clients); err != nil {
		if errors.Is(err, ErrAccessConflict) {
			return err
		}
		return m.failed(err)
	}
	return m.settle(ctx)
}

// Recover must complete before the outer driver reports a restored generation
// as healthy. It is also safe to retry after an uncertain checkpoint fsync.
func (m *AccessManager) Recover(ctx context.Context) error {
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer func() { <-m.gate }()
	if m.closed.Load() {
		return ErrAccessRuntime
	}
	return m.settle(ctx)
}

// Shutdown permanently fences this manager before waiting for in-flight work.
// A failed/closed authorization endpoint must never allow a later Apply to start
// its core again. Recovery uses a newly constructed manager.
func (m *AccessManager) Shutdown(ctx context.Context) error {
	m.closed.Store(true)
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer func() { <-m.gate }()
	return m.stop()
}
