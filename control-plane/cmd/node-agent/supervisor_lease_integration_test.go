package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

type integrationLeaseDriver struct {
	block bool

	started chan struct{}
	stopped chan struct{}

	startOnce sync.Once
	stopOnce  sync.Once

	reconcileCount atomic.Int32
}

func (
	d *integrationLeaseDriver,
) Reconcile(
	ctx context.Context,
	_ model.DesiredState,
) error {
	d.reconcileCount.Add(1)

	d.startOnce.Do(
		func() {
			close(
				d.started,
			)
		},
	)

	if !d.block {
		return nil
	}

	<-ctx.Done()

	d.stopOnce.Do(
		func() {
			close(
				d.stopped,
			)
		},
	)

	return ctx.Err()
}

func (
	d *integrationLeaseDriver,
) Health() (
	bool,
	error,
) {
	return true,
		nil
}

func (
	d *integrationLeaseDriver,
) CurrentVersion() string {
	return "26.7.28"
}

type integrationCPState struct {
	mu sync.Mutex

	deploymentStatus string
	nodeApplied      int64
	appliedVersion   string

	claimCount atomic.Int32
	renewCount atomic.Int32

	applyingCount atomic.Int32
	healthyCount  atomic.Int32
	failedCount   atomic.Int32
	rollbackCount atomic.Int32

	renewStatus int
}

func (
	s *integrationCPState,
) assignment() model.AgentAssignment {
	s.mu.Lock()

	defer s.mu.Unlock()

	return model.AgentAssignment{
		DesiredState: model.DesiredState{
			Generation: 15,

			Core: model.CoreRelease{
				Type: "xray",

				Version: "26.7.28",
			},
		},

		Execution: model.ExecutionAssignment{
			DeploymentID: "11111111-1111-4111-8111-111111111111",

			Generation: 15,

			ExecutionID: "22222222-2222-4222-8222-222222222222",

			ExecutionEpoch: 15,
		},

		DeploymentStatus: s.deploymentStatus,

		NodeAppliedGeneration: s.nodeApplied,

		AppliedCoreVersion: s.appliedVersion,
	}
}

func (
	s *integrationCPState,
) setApplying() {
	s.mu.Lock()

	defer s.mu.Unlock()

	s.deploymentStatus =
		"applying"
}

func (
	s *integrationCPState,
) setHealthy() {
	s.mu.Lock()

	defer s.mu.Unlock()

	s.deploymentStatus =
		"healthy"

	s.nodeApplied =
		15

	s.appliedVersion =
		"26.7.28"
}

func integrationLocalState(
	statePath string,
) (
	agent.LocalState,
	error,
) {
	state :=
		agent.LocalState{
			NodeID: "33333333-3333-4333-8333-333333333333",

			TenantID: "44444444-4444-4444-8444-444444444444",

			AgentToken: "agent-token",

			AppliedGeneration: 14,
		}

	if err :=
		agent.SaveState(
			statePath,
			state,
		); err != nil {

		return agent.LocalState{},
			err
	}

	return state,
		nil
}

func integrationGrant() model.ExecutionLeaseGrant {
	return model.ExecutionLeaseGrant{
		LeaseToken: "ram-only-lease-token",

		LeaseExpiresAt: time.Now().
			UTC().
			Add(
				time.Minute,
			),

		RenewAfterSeconds: 1,
	}
}

func assertLeaseProof(
	t *testing.T,
	report model.DeploymentReport,
) {
	t.Helper()

	if report.OwnerInstanceID !=
		"55555555-5555-4555-8555-555555555555" {

		t.Fatalf(
			"owner_instance_id=%q",
			report.OwnerInstanceID,
		)
	}

	if report.LeaseToken !=
		"ram-only-lease-token" {

		t.Fatal(
			"deployment report missing exact lease proof",
		)
	}

	if report.ExecutionEpoch !=
		15 {

		t.Fatalf(
			"execution_epoch=%d",
			report.ExecutionEpoch,
		)
	}
}

func TestLeaseSupervisorIntegrationSuccessOrdering(
	t *testing.T,
) {
	statePath :=
		filepath.Join(
			t.TempDir(),
			"state.json",
		)

	localState, err :=
		integrationLocalState(
			statePath,
		)

	if err != nil {
		t.Fatal(err)
	}

	driver :=
		&integrationLeaseDriver{
			started: make(
				chan struct{},
			),

			stopped: make(
				chan struct{},
			),
		}

	cp :=
		&integrationCPState{
			deploymentStatus: "pending",

			nodeApplied: 14,
		}

	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					switch r.URL.Path {
					case "/api/v1/agent/assignment":
						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						if err :=
							json.NewEncoder(
								w,
							).Encode(
								cp.assignment(),
							); err != nil {

							t.Error(err)
						}

					case "/api/v1/agent/execution/claim":
						cp.claimCount.Add(
							1,
						)

						var request model.ExecutionLeaseClaimRequest

						if err :=
							json.NewDecoder(
								r.Body,
							).Decode(
								&request,
							); err != nil {

							t.Error(err)
							return
						}

						if request.OwnerInstanceID !=
							"55555555-5555-4555-8555-555555555555" {

							t.Errorf(
								"claim owner=%q",
								request.OwnerInstanceID,
							)
						}

						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						_ =
							json.NewEncoder(
								w,
							).Encode(
								integrationGrant(),
							)

					case "/api/v1/agent/execution/renew":
						cp.renewCount.Add(
							1,
						)

						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						_ =
							json.NewEncoder(
								w,
							).Encode(
								integrationGrant(),
							)

					case "/api/v1/agent/deployment-status":
						var report model.DeploymentReport

						if err :=
							json.NewDecoder(
								r.Body,
							).Decode(
								&report,
							); err != nil {

							t.Error(err)
							return
						}

						assertLeaseProof(
							t,
							report,
						)

						switch report.Status {
						case "applying":
							cp.applyingCount.Add(
								1,
							)

							// Worker must not physically start
							// before Control Plane accepts applying.
							select {
							case <-driver.started:
								t.Error(
									"worker started before applying HTTP 204",
								)

							default:
							}

							cp.setApplying()

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "healthy":
							cp.healthyCount.Add(
								1,
							)

							// Agent must not advance state.json
							// before terminal HTTP 204.
							before, err :=
								agent.LoadState(
									statePath,
								)

							if err != nil {
								t.Error(err)
								return
							}

							if before.AppliedGeneration !=
								14 {

								t.Errorf(
									"state advanced before terminal commit: %d",
									before.AppliedGeneration,
								)
							}

							cp.setHealthy()

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "failed":
							cp.failedCount.Add(
								1,
							)

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "rolled_back":
							cp.rollbackCount.Add(
								1,
							)

							w.WriteHeader(
								http.StatusNoContent,
							)

						default:
							t.Errorf(
								"unexpected deployment status %q",
								report.Status,
							)

							http.Error(
								w,
								"unexpected status",
								http.StatusBadRequest,
							)
						}

					case "/api/v1/agent/health":
						w.WriteHeader(
							http.StatusNoContent,
						)

					default:
						http.NotFound(
							w,
							r,
						)
					}
				},
			),
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	var execution *leasedExecution

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)

	defer cancel()

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution == nil {
		t.Fatal(
			"leased execution not created",
		)
	}

	if execution.Worker == nil {
		t.Fatal(
			"worker not started after applying 204",
		)
	}

	select {
	case <-driver.started:

	case <-time.After(
		time.Second,
	):
		t.Fatal(
			"worker did not start",
		)
	}

	result :=
		<-execution.Worker.done

	if result.Err != nil {
		t.Fatalf(
			"worker error=%v",
			result.Err,
		)
	}

	execution.Worker =
		nil

	execution.PendingResult =
		&result

	// Control Plane currently reports applying.
	// This tick sends terminal healthy with the same lease proof.
	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution != nil {
		t.Fatal(
			"execution not cleared after terminal 204",
		)
	}

	if localState.AppliedGeneration !=
		15 {

		t.Fatalf(
			"in-memory applied=%d want=15",
			localState.AppliedGeneration,
		)
	}

	persisted, err :=
		agent.LoadState(
			statePath,
		)

	if err != nil {
		t.Fatal(err)
	}

	if persisted.AppliedGeneration !=
		15 {

		t.Fatalf(
			"persisted applied=%d want=15",
			persisted.AppliedGeneration,
		)
	}

	if cp.claimCount.Load() !=
		1 {

		t.Fatalf(
			"claim_count=%d want=1",
			cp.claimCount.Load(),
		)
	}

	if cp.applyingCount.Load() !=
		1 {

		t.Fatalf(
			"applying_count=%d want=1",
			cp.applyingCount.Load(),
		)
	}

	if cp.healthyCount.Load() !=
		1 {

		t.Fatalf(
			"healthy_count=%d want=1",
			cp.healthyCount.Load(),
		)
	}

	if cp.failedCount.Load() !=
		0 ||
		cp.rollbackCount.Load() !=
			0 {

		t.Fatal(
			"unexpected failure terminal report",
		)
	}
}

func TestLeaseSupervisorIntegrationRenew409CancelsWorker(
	t *testing.T,
) {
	statePath :=
		filepath.Join(
			t.TempDir(),
			"state.json",
		)

	localState, err :=
		integrationLocalState(
			statePath,
		)

	if err != nil {
		t.Fatal(err)
	}

	driver :=
		&integrationLeaseDriver{
			block: true,

			started: make(
				chan struct{},
			),

			stopped: make(
				chan struct{},
			),
		}

	cp :=
		&integrationCPState{
			deploymentStatus: "pending",

			nodeApplied: 14,

			renewStatus: http.StatusConflict,
		}

	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					switch r.URL.Path {
					case "/api/v1/agent/assignment":
						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						_ =
							json.NewEncoder(
								w,
							).Encode(
								cp.assignment(),
							)

					case "/api/v1/agent/execution/claim":
						cp.claimCount.Add(
							1,
						)

						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						_ =
							json.NewEncoder(
								w,
							).Encode(
								integrationGrant(),
							)

					case "/api/v1/agent/execution/renew":
						cp.renewCount.Add(
							1,
						)

						http.Error(
							w,
							`{"error":"execution lease conflict"}`,
							cp.renewStatus,
						)

					case "/api/v1/agent/deployment-status":
						var report model.DeploymentReport

						if err :=
							json.NewDecoder(
								r.Body,
							).Decode(
								&report,
							); err != nil {

							t.Error(err)
							return
						}

						assertLeaseProof(
							t,
							report,
						)

						switch report.Status {
						case "applying":
							cp.applyingCount.Add(
								1,
							)

							cp.setApplying()

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "healthy":
							cp.healthyCount.Add(
								1,
							)

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "failed":
							cp.failedCount.Add(
								1,
							)

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "rolled_back":
							cp.rollbackCount.Add(
								1,
							)

							w.WriteHeader(
								http.StatusNoContent,
							)

						default:
							http.Error(
								w,
								"unexpected status",
								http.StatusBadRequest,
							)
						}

					case "/api/v1/agent/health":
						w.WriteHeader(
							http.StatusNoContent,
						)

					default:
						http.NotFound(
							w,
							r,
						)
					}
				},
			),
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	var execution *leasedExecution

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			6*time.Second,
		)

	defer cancel()

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution == nil ||
		execution.Worker == nil {

		t.Fatal(
			"blocking worker not started",
		)
	}

	select {
	case <-driver.started:

	case <-time.After(
		time.Second,
	):
		t.Fatal(
			"worker did not start",
		)
	}

	// Grant renew_after_seconds=1.
	// Move beyond NextRenewAt without approaching expiry.
	time.Sleep(
		1100 * time.Millisecond,
	)

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	// renew 409 causes fail-closed cancellation. The tick may
	// return the health result rather than the original 409.
	if err != nil {
		status, ok :=
			agent.HTTPErrorStatus(
				err,
			)

		if ok &&
			status !=
				http.StatusConflict {

			t.Fatalf(
				"unexpected status=%d",
				status,
			)
		}
	}

	if execution == nil {
		t.Fatal(
			"lost execution must remain present until fencing/recovery",
		)
	}

	if !execution.LeaseLost {
		t.Fatal(
			"renew 409 did not mark lease lost",
		)
	}

	if execution.LeaseToken !=
		"" {

		t.Fatal(
			"lease token not cleared after authority loss",
		)
	}

	select {
	case <-driver.stopped:

	case <-time.After(
		time.Second,
	):
		t.Fatal(
			"worker did not quiesce after lease loss",
		)
	}

	result :=
		<-execution.Worker.done

	if !errors.Is(
		result.Err,
		context.Canceled,
	) {
		t.Fatalf(
			"worker result=%v want context.Canceled",
			result.Err,
		)
	}

	execution.Worker =
		nil

	execution.PendingResult =
		&result

	// A later tick must remain fail-closed:
	// no second claim, no second Reconcile and no terminal report.
	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if driver.reconcileCount.Load() !=
		1 {

		t.Fatalf(
			"reconcile_count=%d want=1",
			driver.reconcileCount.Load(),
		)
	}

	if cp.claimCount.Load() !=
		1 {

		t.Fatalf(
			"claim_count=%d want=1",
			cp.claimCount.Load(),
		)
	}

	if cp.renewCount.Load() !=
		1 {

		t.Fatalf(
			"renew_count=%d want=1",
			cp.renewCount.Load(),
		)
	}

	if cp.healthyCount.Load() !=
		0 ||
		cp.failedCount.Load() !=
			0 ||
		cp.rollbackCount.Load() !=
			0 {

		t.Fatal(
			"lease-lost execution emitted forbidden terminal report",
		)
	}

	if localState.AppliedGeneration !=
		14 {

		t.Fatalf(
			"in-memory applied advanced after lease loss: %d",
			localState.AppliedGeneration,
		)
	}

	persisted, err :=
		agent.LoadState(
			statePath,
		)

	if err != nil {
		t.Fatal(err)
	}

	if persisted.AppliedGeneration !=
		14 {

		t.Fatalf(
			"persisted applied advanced after lease loss: %d",
			persisted.AppliedGeneration,
		)
	}
}

func TestLeaseSupervisorIntegrationTransientRenewFailureThenExpiry(
	t *testing.T,
) {
	statePath :=
		filepath.Join(
			t.TempDir(),
			"state.json",
		)

	localState, err :=
		integrationLocalState(
			statePath,
		)

	if err != nil {
		t.Fatal(err)
	}

	driver :=
		&integrationLeaseDriver{
			block: true,

			started: make(
				chan struct{},
			),

			stopped: make(
				chan struct{},
			),
		}

	cp :=
		&integrationCPState{
			deploymentStatus: "pending",

			nodeApplied: 14,
		}

	var leaseExpiry time.Time

	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					switch r.URL.Path {
					case "/api/v1/agent/assignment":
						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						_ =
							json.NewEncoder(
								w,
							).Encode(
								cp.assignment(),
							)

					case "/api/v1/agent/execution/claim":
						cp.claimCount.Add(
							1,
						)

						leaseExpiry =
							time.Now().
								UTC().
								Add(
									3 * time.Second,
								)

						w.Header().Set(
							"Content-Type",
							"application/json",
						)

						_ =
							json.NewEncoder(
								w,
							).Encode(
								model.ExecutionLeaseGrant{
									LeaseToken: "ram-only-lease-token",

									LeaseExpiresAt: leaseExpiry,

									RenewAfterSeconds: 1,
								},
							)

					case "/api/v1/agent/execution/renew":
						cp.renewCount.Add(
							1,
						)

						http.Error(
							w,
							`{"error":"temporary upstream failure"}`,
							http.StatusBadGateway,
						)

					case "/api/v1/agent/deployment-status":
						var report model.DeploymentReport

						if err :=
							json.NewDecoder(
								r.Body,
							).Decode(
								&report,
							); err != nil {

							t.Error(err)
							return
						}

						assertLeaseProof(
							t,
							report,
						)

						switch report.Status {
						case "applying":
							cp.applyingCount.Add(
								1,
							)

							cp.setApplying()

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "healthy":
							cp.healthyCount.Add(
								1,
							)

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "failed":
							cp.failedCount.Add(
								1,
							)

							w.WriteHeader(
								http.StatusNoContent,
							)

						case "rolled_back":
							cp.rollbackCount.Add(
								1,
							)

							w.WriteHeader(
								http.StatusNoContent,
							)

						default:
							http.Error(
								w,
								"unexpected deployment status",
								http.StatusBadRequest,
							)
						}

					case "/api/v1/agent/health":
						w.WriteHeader(
							http.StatusNoContent,
						)

					default:
						http.NotFound(
							w,
							r,
						)
					}
				},
			),
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	var execution *leasedExecution

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			8*time.Second,
		)

	defer cancel()

	// Claim -> applying 204 -> worker starts.
	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution == nil ||
		execution.Worker == nil {

		t.Fatal(
			"worker not started",
		)
	}

	select {
	case <-driver.started:

	case <-time.After(
		time.Second,
	):
		t.Fatal(
			"worker did not start",
		)
	}

	if execution.LeaseLost {
		t.Fatal(
			"freshly claimed lease unexpectedly lost",
		)
	}

	// Wait until first renewal is due but lease remains valid.
	time.Sleep(
		1100 * time.Millisecond,
	)

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	// A transient renew failure is deliberately absorbed by
	// the supervisor while the locally known lease is still
	// valid. The failure is logged, but the worker remains
	// authorized until LeaseExpiresAt.
	if err != nil {
		t.Fatalf(
			"transient renew failure unexpectedly escaped supervisor tick: %v",
			err,
		)
	}

	if execution.LeaseLost {
		t.Fatal(
			"502 incorrectly caused immediate lease loss",
		)
	}

	if execution.LeaseToken == "" {
		t.Fatal(
			"lease token cleared before authority expired",
		)
	}

	select {
	case <-driver.stopped:
		t.Fatal(
			"worker stopped on transient 502 before lease expiry",
		)

	default:
	}

	if driver.reconcileCount.Load() !=
		1 {

		t.Fatalf(
			"reconcile_count=%d want=1 after transient failure",
			driver.reconcileCount.Load(),
		)
	}

	if localState.AppliedGeneration !=
		14 {

		t.Fatalf(
			"state advanced during transient renew failure: %d",
			localState.AppliedGeneration,
		)
	}

	// Wait past the authoritative local lease deadline.
	wait :=
		time.Until(
			leaseExpiry,
		) +
			250*time.Millisecond

	if wait > 0 {
		time.Sleep(
			wait,
		)
	}

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution == nil {
		t.Fatal(
			"expired execution must remain until fencing/recovery",
		)
	}

	if !execution.LeaseLost {
		t.Fatal(
			"local lease expiry did not mark authority lost",
		)
	}

	if execution.LeaseToken !=
		"" {

		t.Fatal(
			"lease token not cleared after local expiry",
		)
	}

	select {
	case <-driver.stopped:

	case <-time.After(
		time.Second,
	):
		t.Fatal(
			"worker did not quiesce after local lease expiry",
		)
	}

	result :=
		<-execution.Worker.done

	if !errors.Is(
		result.Err,
		context.Canceled,
	) {
		t.Fatalf(
			"worker result=%v want context.Canceled",
			result.Err,
		)
	}

	execution.Worker =
		nil

	execution.PendingResult =
		&result

	// One more tick proves fail-closed persistence:
	// no reclaim, no second Reconcile, no terminal report.
	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			"55555555-5555-4555-8555-555555555555",
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if driver.reconcileCount.Load() !=
		1 {

		t.Fatalf(
			"reconcile_count=%d want=1",
			driver.reconcileCount.Load(),
		)
	}

	if cp.claimCount.Load() !=
		1 {

		t.Fatalf(
			"claim_count=%d want=1",
			cp.claimCount.Load(),
		)
	}

	if cp.renewCount.Load() !=
		1 {

		t.Fatalf(
			"renew_count=%d want=1",
			cp.renewCount.Load(),
		)
	}

	if cp.healthyCount.Load() !=
		0 ||
		cp.failedCount.Load() !=
			0 ||
		cp.rollbackCount.Load() !=
			0 {

		t.Fatal(
			"expired execution emitted forbidden terminal report",
		)
	}

	if localState.AppliedGeneration !=
		14 {

		t.Fatalf(
			"in-memory state advanced after expiry: %d",
			localState.AppliedGeneration,
		)
	}

	persisted, err :=
		agent.LoadState(
			statePath,
		)

	if err != nil {
		t.Fatal(err)
	}

	if persisted.AppliedGeneration !=
		14 {

		t.Fatalf(
			"persisted state advanced after expiry: %d",
			persisted.AppliedGeneration,
		)
	}
}
