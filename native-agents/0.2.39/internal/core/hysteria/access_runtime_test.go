package hysteria

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type accessRuntimeFixture struct {
	events                            []string
	running                           bool
	stopError, startError, readyError error
	onStart                           func()
}

func (r *accessRuntimeFixture) Stop(ctx context.Context) error {
	r.events = append(r.events, "stop")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if r.stopError != nil {
		return r.stopError
	}
	r.running = false
	return nil
}
func (r *accessRuntimeFixture) Start(ctx context.Context) error {
	r.events = append(r.events, "start")
	r.running = true
	if r.onStart != nil {
		r.onStart()
	}
	return r.startError
}
func (r *accessRuntimeFixture) Ready(context.Context) error {
	r.events = append(r.events, "ready")
	return r.readyError
}
func managerFixture(t *testing.T) (*AccessManager, *accessRuntimeFixture, string) {
	t.Helper()
	_, path := persistentFixture(t)
	runtime := &accessRuntimeFixture{}
	m, err := NewAccessManager(path, runtime, func(context.Context) { runtime.events = append(runtime.events, "capture") })
	if err != nil {
		t.Fatal(err)
	}
	return m, runtime, path
}
func policyA() []Client  { return []Client{{"client-a", strings.Repeat("a", 32)}} }
func policyAB() []Client { return append(policyA(), Client{"client-b", strings.Repeat("b", 32)}) }
func TestAccessRuntimeRemovalRotationAndAddition(t *testing.T) {
	m, r, _ := managerFixture(t)
	ctx := context.Background()
	if err := m.Apply(ctx, 1, policyA()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.events, []string{"capture", "stop", "start", "ready"}) {
		t.Fatal(r.events)
	}
	r.events = nil
	if err := m.Apply(ctx, 2, policyAB()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.events, []string{"start", "ready"}) {
		t.Fatal("addition restarted the core", r.events)
	}
	for gen, clients := range map[int64][]Client{3: {{"client-a", strings.Repeat("c", 32)}, {"client-b", strings.Repeat("b", 32)}}} {
		r.events = nil
		if err := m.Apply(ctx, gen, clients); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(r.events, []string{"capture", "stop", "start", "ready"}) {
			t.Fatal("rotation did not quiesce core", r.events)
		}
	}
	r.events = nil
	if err := m.Apply(ctx, 4, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.events, []string{"capture", "stop", "start", "ready"}) {
		t.Fatal("deny all did not quiesce core", r.events)
	}
	_, pending := m.policy.PendingRevocations()
	if len(pending) != 0 || !r.running {
		t.Fatal("revoke completion state invalid")
	}
}
func TestAccessRuntimeFailedStopRetainsPendingAndRestartRecovers(t *testing.T) {
	m, r, path := managerFixture(t)
	ctx := context.Background()
	if err := m.Apply(ctx, 1, policyAB()); err != nil {
		t.Fatal(err)
	}
	r.stopError = errors.New("synthetic stop failure")
	r.events = nil
	if err := m.Apply(ctx, 2, policyA()); !errors.Is(err, ErrRuntimeStop) {
		t.Fatal("failed stop accepted")
	}
	if !reflect.DeepEqual(r.events, []string{"capture", "stop"}) {
		t.Fatal("started after failed stop")
	}
	restored, err := OpenPersistentAuthorizer(path)
	if err != nil {
		t.Fatal(err)
	}
	_, pending := restored.PendingRevocations()
	if !reflect.DeepEqual(pending, []string{"client-b"}) {
		t.Fatal("lost pending revoke")
	}
	if _, allowed := restored.allowed(strings.Repeat("b", 32)); allowed {
		t.Fatal("removed credential restored")
	}
	r.stopError = nil
	r.events = nil
	m, err = NewAccessManager(path, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.events, []string{"stop", "start", "ready"}) {
		t.Fatal("restart did not stop old invocation")
	}
	_, pending = m.policy.PendingRevocations()
	if len(pending) != 0 {
		t.Fatal("pending revoke not resolved")
	}
}
func TestAccessRuntimeCancellationAfterStartUsesIndependentCleanup(t *testing.T) {
	m, r, _ := managerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	r.onStart = cancel
	if err := m.Apply(ctx, 1, policyA()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled start accepted")
	}
	if r.running || m.synchronized || !reflect.DeepEqual(r.events, []string{"capture", "stop", "start", "capture", "stop"}) {
		t.Fatal("cancelled start left runtime active", r.events)
	}
}
func TestAccessRuntimeReadinessFailureDoesNotRestoreRevokedAccess(t *testing.T) {
	m, r, path := managerFixture(t)
	ctx := context.Background()
	if err := m.Apply(ctx, 1, policyAB()); err != nil {
		t.Fatal(err)
	}
	r.readyError = errors.New("synthetic readiness failure")
	if err := m.Apply(ctx, 2, policyA()); !errors.Is(err, ErrAccessRuntime) {
		t.Fatal("unhealthy core accepted")
	}
	if r.running || m.synchronized {
		t.Fatal("unhealthy core left active")
	}
	a, err := OpenPersistentAuthorizer(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, allowed := a.allowed(strings.Repeat("b", 32)); allowed {
		t.Fatal("failure regranted revoked credential")
	}
}
func TestAccessRuntimeJournalFailureStopsWithoutStarting(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(map[bool]string{false: "staging", true: "directory_sync"}[afterRename], func(t *testing.T) {
			m, r, path := managerFixture(t)
			ctx := context.Background()
			if err := m.Apply(ctx, 1, policyAB()); err != nil {
				t.Fatal(err)
			}
			m.policy.persistent.save = func(path string, raw []byte) (bool, error) {
				if afterRename {
					if _, err := saveAccessRecord(path, raw); err != nil {
						t.Fatal(err)
					}
				}
				return afterRename, errors.New("synthetic storage error")
			}
			r.events = nil
			if err := m.Apply(ctx, 2, policyA()); !errors.Is(err, ErrAccessJournal) {
				t.Fatal("disk failure accepted")
			}
			if r.running || !reflect.DeepEqual(r.events, []string{"capture", "stop"}) {
				t.Fatal("disk failure left runtime active")
			}
			a, err := OpenPersistentAuthorizer(path)
			if err != nil {
				t.Fatal(err)
			}
			_, allowed := a.allowed(strings.Repeat("b", 32))
			if allowed == afterRename {
				t.Fatal("durable boundary mismatch")
			}
			m.policy.persistent.save = saveAccessRecord
			if err = m.Apply(ctx, 2, policyA()); err != nil {
				t.Fatal("durable retry failed", err)
			}
		})
	}
}
func TestAccessRuntimeAcknowledgementFailureStaysStopped(t *testing.T) {
	m, r, _ := managerFixture(t)
	ctx := context.Background()
	if err := m.Apply(ctx, 1, policyAB()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	m.policy.persistent.save = func(path string, raw []byte) (bool, error) {
		calls++
		if calls == 2 {
			return false, errors.New("synthetic acknowledgement failure")
		}
		return saveAccessRecord(path, raw)
	}
	if err := m.Apply(ctx, 2, policyA()); !errors.Is(err, ErrAccessJournal) {
		t.Fatal("ack failure accepted")
	}
	_, pending := m.policy.PendingRevocations()
	if r.running || len(pending) != 1 {
		t.Fatal("lost incomplete acknowledgement")
	}
	m.policy.persistent.save = saveAccessRecord
	if err := m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestAccessRuntimeInvalidOrStaleInputPreservesRuntime(t *testing.T) {
	m, r, _ := managerFixture(t)
	ctx := context.Background()
	if err := m.Apply(ctx, 2, policyA()); err != nil {
		t.Fatal(err)
	}
	r.events = nil
	for _, input := range []struct {
		gen     int64
		clients []Client
	}{{1, policyA()}, {2, policyAB()}, {3, []Client{{"invalid id", "secret"}}}, {0, nil}} {
		if err := m.Apply(ctx, input.gen, input.clients); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if len(r.events) != 0 || !r.running {
		t.Fatal("invalid input disrupted current core")
	}
}
func TestAccessRuntimeMissingCorruptAndCancelledStartup(t *testing.T) {
	m, r, path := managerFixture(t)
	r.running = true
	if err := m.Recover(context.Background()); err != nil || r.running {
		t.Fatal("missing checkpoint revived old core")
	}
	r.running = true
	r.events = nil
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAccessManager(path, r, nil); !errors.Is(err, ErrAccessJournal) || r.running {
		t.Fatal("corrupt checkpoint did not stop core")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.events = nil
	if err := m.Apply(ctx, 1, policyA()); !errors.Is(err, context.Canceled) || len(r.events) != 0 {
		t.Fatal("already cancelled work mutated runtime")
	}
}
func TestAccessRuntimeWaitingForGateHonorsCancellation(t *testing.T) {
	m, r, _ := managerFixture(t)
	m.gate <- struct{}{}
	defer func() { <-m.gate }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.Recover(ctx); !errors.Is(err, context.DeadlineExceeded) || len(r.events) != 0 {
		t.Fatal("queued cancellation mutated runtime")
	}
}
func TestAccessRuntimeShutdownPermanentlyFencesLaterWork(t *testing.T) {
	m, r, _ := managerFixture(t)
	ctx := context.Background()
	if err := m.Apply(ctx, 1, policyA()); err != nil {
		t.Fatal(err)
	}
	if err := m.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	r.events = nil
	if err := m.Apply(ctx, 2, policyAB()); !errors.Is(err, ErrAccessRuntime) {
		t.Fatal("closed manager accepted desired state")
	}
	if err := m.Recover(ctx); !errors.Is(err, ErrAccessRuntime) {
		t.Fatal("closed manager accepted recovery")
	}
	if r.running || len(r.events) != 0 {
		t.Fatal("closed manager mutated runtime")
	}
}
func TestAccessRuntimeShutdownFencesInFlightStart(t *testing.T) {
	m, r, _ := managerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	r.onStart = func() { close(entered); <-release }
	result := make(chan error, 1)
	go func() { result <- m.Apply(context.Background(), 1, policyA()) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled shutdown did not surface incomplete wait")
	}
	close(release)
	if err := <-result; !errors.Is(err, ErrAccessRuntime) {
		t.Fatal("start ignored shutdown fence")
	}
	if r.running || m.synchronized {
		t.Fatal("in-flight start remained active after shutdown")
	}
}
