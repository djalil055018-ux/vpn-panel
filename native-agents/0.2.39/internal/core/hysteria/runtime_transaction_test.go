package hysteria

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"vpn-platform/internal/model"
)

type transactionCore struct {
	store         *revisionStore
	running       bool
	stops, starts int
	failRevision  string
	onStart       func()
	stoppedAt     []string
}

func (c *transactionCore) Stop(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.stops++
	c.running = false
	revision, err := c.store.current(ctx)
	if err != nil {
		return err
	}
	id := ""
	if revision != nil {
		id = revision.id
	}
	c.stoppedAt = append(c.stoppedAt, id)
	return nil
}
func (c *transactionCore) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	revision, err := c.store.current(ctx)
	if err != nil || revision == nil {
		return ErrRuntimeRevision
	}
	if c.onStart != nil {
		c.onStart()
	}
	if revision.id == c.failRevision {
		return ErrAccessRuntime
	}
	if !c.running {
		c.starts++
	}
	c.running = true
	return nil
}
func (c *transactionCore) Ready(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !c.running {
		return ErrAccessRuntime
	}
	return nil
}
func (c *transactionCore) Stopped(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.running {
		return ErrRuntimeStop
	}
	return nil
}
func transactionFixture(t *testing.T) (*runtimeTransaction, *transactionCore, model.DesiredState, *runtimeRevision) {
	t.Helper()
	store, state := revisionFixture(t)
	core := &transactionCore{store: store}
	tx, err := newRuntimeTransaction(store, core, filepath.Join(t.TempDir(), "access.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := store.stage(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.applyPrepared(context.Background(), revision, 1, clientsForState(state)); err != nil {
		t.Fatal(err)
	}
	return tx, core, state, revision
}
func TestRuntimeTransactionAdditionsPreserveInvocationAndStructuralChangesStopBeforeSwitch(t *testing.T) {
	tx, core, state, first := transactionFixture(t)
	ctx := context.Background()
	stops, starts := core.stops, core.starts
	state.Services[0].Clients = append(state.Services[0].Clients, model.ClientSpec{ID: "77777777-7777-4777-8777-777777777777", StatsKey: "88888888-8888-4888-8888-888888888888"})
	added, err := tx.store.stage(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.applyPrepared(ctx, added, 2, clientsForState(state)); err != nil {
		t.Fatal(err)
	}
	if core.stops != stops || core.starts != starts {
		t.Fatal("addition restarted existing invocation")
	}
	state.Services[0].Port = 444
	changed, err := tx.store.stage(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.applyPrepared(ctx, changed, 3, clientsForState(state)); err != nil {
		t.Fatal(err)
	}
	if core.stops != stops+1 || core.starts != starts+1 || core.stoppedAt[len(core.stoppedAt)-1] != first.id {
		t.Fatal("structural switch did not stop old revision first")
	}
}
func TestRuntimeTransactionRollbackNeverRestoresRevokedCredentials(t *testing.T) {
	tx, core, state, first := transactionFixture(t)
	ctx := context.Background()
	removed := state.Services[0].Clients[0].ID
	state.Services[0].Clients = nil
	state.Services[0].Port = 444
	changed, err := tx.store.stage(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	core.failRevision = changed.id
	if err = tx.applyPrepared(ctx, changed, 2, nil); err == nil {
		t.Fatal("failed candidate reported success")
	}
	active, err := tx.store.current(ctx)
	if err != nil || active.id != first.id || !core.running {
		t.Fatal("previous configuration was not recovered")
	}
	if _, ok := tx.access.policy.allowed(removed); ok {
		t.Fatal("rollback restored revoked credential")
	}
	reopened, err := OpenPersistentAuthorizer(tx.access.policy.persistent.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.allowed(removed); ok {
		t.Fatal("durable rollback restored revoked credential")
	}
	generation, pending := reopened.PendingRevocations()
	if generation != 2 || len(pending) != 0 {
		t.Fatal("new durable policy did not converge")
	}
}
func TestRuntimeTransactionCancelledLeaseRestoresPointerButNeverRestarts(t *testing.T) {
	tx, core, state, first := transactionFixture(t)
	state.Services[0].Port = 444
	changed, err := tx.store.stage(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	core.onStart = cancel
	if err = tx.applyPrepared(ctx, changed, 2, clientsForState(state)); err == nil {
		t.Fatal("cancelled lease succeeded")
	}
	active, err := tx.store.current(context.Background())
	if err != nil || active.id != first.id || core.running {
		t.Fatal("expired lease restarted rollback configuration")
	}
}
func TestRuntimeTransactionClosedAuthorizationPermanentlyFencesApply(t *testing.T) {
	tx, core, state, first := transactionFixture(t)
	ctx := context.Background()
	if err := tx.access.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	starts := core.starts
	if err := tx.applyPrepared(ctx, first, 2, clientsForState(state)); !errors.Is(err, ErrAccessRuntime) {
		t.Fatal("closed authorization accepted apply")
	}
	if core.running || core.starts != starts {
		t.Fatal("closed authorization restarted core")
	}
}
func TestRuntimeTransactionIdleAndResume(t *testing.T) {
	tx, core, state, first := transactionFixture(t)
	ctx := context.Background()
	clients := clientsForState(state)
	state.Services = nil
	idle, err := tx.store.stage(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.applyPrepared(ctx, idle, 2, nil); err != nil {
		t.Fatal(err)
	}
	if core.running {
		t.Fatal("idle revision left core running")
	}
	if err = tx.applyPrepared(ctx, first, 3, clients); err != nil || !core.running {
		t.Fatal("resume failed", err)
	}
}
func TestRuntimeTransactionCorruptCandidateAndStalePolicyDoNotMutateLiveRuntime(t *testing.T) {
	tx, core, state, first := transactionFixture(t)
	ctx := context.Background()
	state.Services[0].Port = 444
	changed, err := tx.store.stage(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	stops, starts := core.stops, core.starts
	if err = tx.applyPrepared(ctx, changed, 1, nil); err == nil {
		t.Fatal("conflicting generation accepted")
	}
	if err = os.WriteFile(filepath.Join(tx.store.versions(), changed.id, "config.json"), []byte(`{}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err = tx.applyPrepared(ctx, changed, 2, nil); err == nil {
		t.Fatal("corrupt candidate accepted")
	}
	active, err := tx.store.current(ctx)
	if err != nil || active.id != first.id || !core.running || core.stops != stops || core.starts != starts {
		t.Fatal("rejected candidate disturbed runtime")
	}
}
