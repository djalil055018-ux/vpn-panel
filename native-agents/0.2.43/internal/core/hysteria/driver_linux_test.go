//go:build linux

package hysteria

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func driverFixture(t *testing.T) (*Driver, *transactionCore, model.DesiredState, *runtimeRevision) {
	t.Helper()
	tx, core, state, first := transactionFixture(t)
	fence := desiredFence{path: tx.access.policy.persistent.path + ".desired"}
	if err := fence.commit(context.Background(), state, 0); err != nil {
		t.Fatal(err)
	}
	driver, err := newDriver(tx, 65534, 65534)
	if err != nil {
		t.Fatal(err)
	}
	driver.validate = func(context.Context, model.DesiredState, int, int) error { return nil }
	return driver, core, state, first
}
func TestDriverPreflightFailurePreservesRuntimeAndAuthorization(t *testing.T) {
	driver, core, state, first := driverFixture(t)
	starts, stops := core.starts, core.stops
	old := state.Services[0].Clients[0].ID
	driver.validate = func(context.Context, model.DesiredState, int, int) error { return ErrPreflight }
	state.Generation = 2
	state.Services[0].Port = 444
	state.Services[0].Clients = nil
	if err := driver.Reconcile(context.Background(), state); !errors.Is(err, ErrPreflight) {
		t.Fatal("invalid candidate passed preflight")
	}
	current, err := driver.transaction.store.current(context.Background())
	if err != nil || current.id != first.id || !core.running || core.starts != starts || core.stops != stops {
		t.Fatal("preflight failure mutated live runtime")
	}
	if _, ok := driver.transaction.access.policy.allowed(old); !ok {
		t.Fatal("preflight failure changed policy")
	}
}

func TestDriverRejectsSameGenerationStructuralMutationWithoutRestart(t *testing.T) {
	driver, core, state, first := driverFixture(t)
	state.Services[0].Port = 444
	starts, stops := core.starts, core.stops
	if err := driver.Reconcile(context.Background(), state); !errors.Is(err, ErrAccessConflict) {
		t.Fatal("same desired generation changed listener")
	}
	current, err := driver.transaction.store.current(context.Background())
	if err != nil || current.id != first.id || core.starts != starts || core.stops != stops {
		t.Fatal("rejected generation disturbed core")
	}
}

func TestDriverReconstructionStopsOnMissingDesiredCheckpoint(t *testing.T) {
	driver, core, _, _ := driverFixture(t)
	if os.Remove(driver.fence.path) != nil {
		t.Fatal("checkpoint removal fixture failed")
	}
	if _, err := newDriver(driver.transaction, 65534, 65534); !errors.Is(err, ErrDesiredFence) {
		t.Fatal("missing desired checkpoint reconstructed")
	}
	if core.running {
		t.Fatal("damaged checkpoint left runtime running")
	}
}

func TestDriverRollbackRetainsDesiredIntentFenceForRetry(t *testing.T) {
	driver, core, state, first := driverFixture(t)
	ctx := context.Background()
	state.Generation = 2
	state.Services[0].Port = 444
	candidate, err := driver.prepare(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	core.failRevision = candidate.id
	if err = driver.Reconcile(ctx, state); err == nil {
		t.Fatal("failed candidate accepted")
	}
	current, err := driver.transaction.store.current(ctx)
	if err != nil || current.id != first.id {
		t.Fatal("rollback did not restore runtime")
	}
	conflict := state
	conflict.Services = append([]model.ServiceSpec(nil), state.Services...)
	conflict.Services[0].Port = 445
	if err = driver.Reconcile(ctx, conflict); !errors.Is(err, ErrAccessConflict) {
		t.Fatal("rollback discarded desired intent fence")
	}
	core.failRevision = ""
	if err = driver.Reconcile(ctx, state); err != nil {
		t.Fatal("identical candidate retry failed", err)
	}
}
func TestDriverTLSRenewalPreservesPolicyAndKeepsOriginalKeyPrivate(t *testing.T) {
	driver, core, state, first := driverFixture(t)
	ctx := context.Background()
	credential := state.Services[0].Clients[0].ID
	root := filepath.Join(driver.transaction.store.installer.base, "certificates", tlsFixtureID)
	addTLSVersion(t, root, "renewed", time.Now().Add(2*time.Hour))
	if err := rotateTLSVersion(root, "renewed"); err != nil {
		t.Fatal(err)
	}
	stops := core.stops
	if err := driver.RefreshTLSCertificateContext(ctx, tlsFixtureID, "tls-probe.invalid"); err != nil {
		t.Fatal(err)
	}
	current, err := driver.transaction.store.current(ctx)
	if err != nil || current.id == first.id || !core.running || core.stops != stops+1 {
		t.Fatal("renewal did not activate new TLS revision")
	}
	if _, ok := driver.transaction.access.policy.allowed(credential); !ok {
		t.Fatal("renewal cleared access policy")
	}
	generation, pending := driver.transaction.access.policy.PendingRevocations()
	if generation != 1 || len(pending) != 0 {
		t.Fatal("renewal changed authorization generation")
	}
	info, err := os.Stat(filepath.Join(root, "current", "private.key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("renewal changed original key permissions")
	}
	if healthy, err := driver.Health(); err != nil || !healthy || driver.CurrentVersion() != state.Core.Version {
		t.Fatal("renewal health/version invalid")
	}
	stops = core.stops
	if err = driver.RefreshTLSCertificateContext(ctx, tlsFixtureID, "tls-probe.invalid"); err != nil || core.stops != stops {
		t.Fatal("unchanged renewal restarted core")
	}
}
func TestDriverFailedTLSRenewalRecoversOldMaterialWithExistingAccess(t *testing.T) {
	driver, core, state, first := driverFixture(t)
	ctx := context.Background()
	root := filepath.Join(driver.transaction.store.installer.base, "certificates", tlsFixtureID)
	addTLSVersion(t, root, "renewed", time.Now().Add(2*time.Hour))
	if err := rotateTLSVersion(root, "renewed"); err != nil {
		t.Fatal(err)
	}
	candidate, err := driver.prepare(ctx, first.state)
	if err != nil {
		t.Fatal(err)
	}
	core.failRevision = candidate.id
	if err = driver.RefreshTLSCertificateContext(ctx, tlsFixtureID, "tls-probe.invalid"); err == nil {
		t.Fatal("failed renewal reported success")
	}
	current, err := driver.transaction.store.current(ctx)
	if err != nil || current.id != first.id || !core.running {
		t.Fatal("old certificate revision not recovered")
	}
	if _, ok := driver.transaction.access.policy.allowed(state.Services[0].Clients[0].ID); !ok {
		t.Fatal("renewal rollback lost access")
	}
}
func TestDriverShutdownDuringPreparationPreventsActivation(t *testing.T) {
	driver, core, state, first := driverFixture(t)
	ctx := context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	driver.validate = func(context.Context, model.DesiredState, int, int) error { close(entered); <-release; return nil }
	state.Generation = 2
	state.Services[0].Port = 444
	result := make(chan error, 1)
	go func() { result <- driver.Reconcile(ctx, state) }()
	<-entered
	if err := driver.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("fenced candidate activated")
	}
	current, err := driver.transaction.store.current(ctx)
	if err != nil || current.id != first.id || core.running {
		t.Fatal("shutdown raced into new invocation")
	}
}
func TestDriverSerializesRenewalAndReconcileWithoutLosingRevocation(t *testing.T) {
	driver, _, state, _ := driverFixture(t)
	ctx := context.Background()
	credential := state.Services[0].Clients[0].ID
	root := filepath.Join(driver.transaction.store.installer.base, "certificates", tlsFixtureID)
	addTLSVersion(t, root, "renewed", time.Now().Add(2*time.Hour))
	if err := rotateTLSVersion(root, "renewed"); err != nil {
		t.Fatal(err)
	}
	state.Generation = 2
	state.Services[0].Clients = nil
	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); results <- driver.Reconcile(ctx, state) }()
	go func() {
		defer wg.Done()
		results <- driver.RefreshTLSCertificateContext(ctx, tlsFixtureID, "tls-probe.invalid")
	}()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := driver.transaction.access.policy.allowed(credential); ok {
		t.Fatal("concurrent renewal restored revoked credential")
	}
	generation, _ := driver.transaction.access.policy.PendingRevocations()
	if generation != 2 {
		t.Fatal("concurrent renewal rewound policy")
	}
}
func TestDriverRecoveryRequiresCheckpointAndHonorsShutdown(t *testing.T) {
	driver, core, _, _ := driverFixture(t)
	ctx := context.Background()
	store := driver.transaction.store
	tx, err := newRuntimeTransaction(store, core, filepath.Join(t.TempDir(), "missing-policy.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := newDriver(tx, 65534, 65534)
	if err != nil {
		t.Fatal(err)
	}
	if err = recovered.Recover(ctx); err != nil || core.running {
		t.Fatal("missing checkpoint revived old configuration")
	}
	if err = recovered.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err = recovered.Recover(ctx); err == nil {
		t.Fatal("closed runtime recovered")
	}
}
