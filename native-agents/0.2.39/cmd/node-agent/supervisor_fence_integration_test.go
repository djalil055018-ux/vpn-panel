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

const (
	fenceIntegrationOwner = "55555555-5555-4555-8555-555555555555"

	fenceIntegrationRequestID = "66666666-6666-4666-8666-666666666666"

	fenceIntegrationProof = "ram-only-lease-token"
)

type fenceIntegrationCP struct {
	mu sync.Mutex

	deploymentStatus string
	nodeApplied      int64

	fenceRequested    bool
	fenceVisible      bool
	fenceAcknowledged bool

	renewConflict bool

	loseFirstACKResponse bool

	assignmentCount atomic.Int32
	claimCount      atomic.Int32
	renewCount      atomic.Int32
	applyingCount   atomic.Int32
	terminalCount   atomic.Int32
	ackCount        atomic.Int32
}

func (
	s *fenceIntegrationCP,
) fenceRequest() *model.ExecutionFenceRequest {
	return &model.ExecutionFenceRequest{
		ID: fenceIntegrationRequestID,

		DeploymentID: "11111111-1111-4111-8111-111111111111",

		Generation: 15,

		ExecutionID: "22222222-2222-4222-8222-222222222222",

		ExecutionEpoch: 15,

		State: "requested",

		TargetOwnerInstanceID: fenceIntegrationOwner,

		Reason: "integration physical fencing",
	}
}

func (
	s *fenceIntegrationCP,
) assignment() model.AgentAssignment {
	s.mu.Lock()
	defer s.mu.Unlock()

	assignment :=
		model.AgentAssignment{
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
		}

	if s.fenceRequested &&
		s.fenceVisible &&
		!s.fenceAcknowledged {

		assignment.FenceRequest =
			s.fenceRequest()
	}

	return assignment
}

func (
	s *fenceIntegrationCP,
) requestFence(
	visible bool,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fenceRequested =
		true

	s.fenceVisible =
		visible
}

func (
	s *fenceIntegrationCP,
) revealFence() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fenceVisible =
		true
}

func (
	s *fenceIntegrationCP,
) setApplying() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deploymentStatus =
		"applying"
}

func (
	s *fenceIntegrationCP,
) commitFenceACK() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fenceAcknowledged =
		true

	// Real Control Plane stops returning an acknowledged
	// fence through AgentAssignment.
	s.fenceVisible =
		false
}

func (
	s *fenceIntegrationCP,
) acknowledged() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.fenceAcknowledged
}

func newFenceIntegrationServer(
	t *testing.T,
	cp *fenceIntegrationCP,
) *httptest.Server {
	t.Helper()

	return httptest.NewServer(
		http.HandlerFunc(
			func(
				w http.ResponseWriter,
				r *http.Request,
			) {
				switch r.URL.Path {
				case "/api/v1/agent/assignment":
					cp.assignmentCount.Add(
						1,
					)

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
						fenceIntegrationOwner {

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

					var request model.ExecutionLeaseRenewRequest

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
						fenceIntegrationOwner {

						t.Errorf(
							"renew owner=%q",
							request.OwnerInstanceID,
						)
					}

					if request.LeaseToken !=
						fenceIntegrationProof {

						t.Fatal(
							"renew missing original lease authority token",
						)
					}

					cp.mu.Lock()

					conflict :=
						cp.renewConflict &&
							cp.fenceRequested

					cp.mu.Unlock()

					if conflict {
						http.Error(
							w,
							`{"error":"execution fence requested"}`,
							http.StatusConflict,
						)

						return
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

					case "healthy",
						"failed",
						"rolled_back":

						cp.terminalCount.Add(
							1,
						)

						t.Errorf(
							"fenced execution emitted forbidden terminal report %q",
							report.Status,
						)

						w.WriteHeader(
							http.StatusConflict,
						)

					default:
						http.Error(
							w,
							"unexpected deployment status",
							http.StatusBadRequest,
						)
					}

				case "/api/v1/agent/execution/fence-ack":
					call :=
						cp.ackCount.Add(
							1,
						)

					var request model.ExecutionFenceAckRequest

					if err :=
						json.NewDecoder(
							r.Body,
						).Decode(
							&request,
						); err != nil {

						t.Error(err)
						return
					}

					if request.FenceRequestID !=
						fenceIntegrationRequestID {

						t.Errorf(
							"ACK request_id=%q",
							request.FenceRequestID,
						)
					}

					if request.OwnerInstanceID !=
						fenceIntegrationOwner {

						t.Errorf(
							"ACK owner=%q",
							request.OwnerInstanceID,
						)
					}

					if request.FenceProofToken !=
						fenceIntegrationProof {

						t.Fatal(
							"ACK did not carry retained RAM-only proof",
						)
					}

					if request.Execution.DeploymentID !=
						"11111111-1111-4111-8111-111111111111" ||
						request.Execution.ExecutionID !=
							"22222222-2222-4222-8222-222222222222" ||
						request.Execution.ExecutionEpoch !=
							15 ||
						request.Execution.Generation !=
							15 {

						t.Fatal(
							"ACK execution identity mismatch",
						)
					}

					// Commit first. This models the real transaction:
					// request=acknowledged + lease=fenced.
					cp.commitFenceACK()

					if cp.loseFirstACKResponse &&
						call == 1 {

						// Transaction has committed, but Agent does
						// not receive the successful response.
						http.Error(
							w,
							"simulated lost ACK response",
							http.StatusBadGateway,
						)

						return
					}

					w.Header().Set(
						"Content-Type",
						"application/json",
					)

					_ =
						json.NewEncoder(
							w,
						).Encode(
							model.ExecutionFenceRequest{
								ID: fenceIntegrationRequestID,

								State: "acknowledged",
							},
						)

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
}

func startBlockingFenceExecution(
	t *testing.T,
	ctx context.Context,
	client *agent.Client,
	driver *integrationLeaseDriver,
	statePath string,
	localState *agent.LocalState,
	execution **leasedExecution,
) {
	t.Helper()

	if err :=
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			localState,
			fenceIntegrationOwner,
			execution,
		); err != nil {

		t.Fatal(err)
	}

	if *execution == nil ||
		(*execution).Worker == nil {

		t.Fatal(
			"leased blocking worker was not started",
		)
	}

	select {
	case <-driver.started:

	case <-time.After(
		time.Second,
	):
		t.Fatal(
			"blocking worker did not start",
		)
	}

	if (*execution).LeaseToken !=
		fenceIntegrationProof {

		t.Fatal(
			"initial execution authority token mismatch",
		)
	}

	if (*execution).FenceProofToken !=
		fenceIntegrationProof {

		t.Fatal(
			"initial fencing proof not retained",
		)
	}
}

func consumeCancelledFenceWorker(
	t *testing.T,
	driver *integrationLeaseDriver,
	execution *leasedExecution,
) {
	t.Helper()

	if execution == nil ||
		execution.Worker == nil {

		t.Fatal(
			"expected active worker before quiescence",
		)
	}

	select {
	case <-driver.stopped:

	case <-time.After(
		time.Second,
	):
		t.Fatal(
			"worker did not physically quiesce",
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
}

func TestFenceIntegrationAssignmentFenceBeforeRenew(
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
		&fenceIntegrationCP{
			deploymentStatus: "pending",

			nodeApplied: 14,
		}

	server :=
		newFenceIntegrationServer(
			t,
			cp,
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)

	defer cancel()

	var execution *leasedExecution

	startBlockingFenceExecution(
		t,
		ctx,
		client,
		driver,
		statePath,
		&localState,
		&execution,
	)

	// Guarantee that assignment observation wins over renewal.
	execution.NextRenewAt =
		time.Now().
			Add(
				time.Hour,
			).
			UTC()

	cp.requestFence(
		true,
	)

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			fenceIntegrationOwner,
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution == nil ||
		execution.FenceRequest == nil {

		t.Fatal(
			"assignment fence was not retained in RAM",
		)
	}

	if !execution.LeaseLost {
		t.Fatal(
			"assignment fence did not revoke authority",
		)
	}

	if execution.LeaseToken != "" {
		t.Fatal(
			"authority token survived assignment fence",
		)
	}

	if execution.FenceProofToken !=
		fenceIntegrationProof {

		t.Fatal(
			"assignment fence destroyed RAM proof",
		)
	}

	if cp.renewCount.Load() !=
		0 {

		t.Fatalf(
			"renew_count=%d want=0",
			cp.renewCount.Load(),
		)
	}

	if cp.ackCount.Load() !=
		0 {

		t.Fatal(
			"ACK occurred before worker quiescence",
		)
	}

	consumeCancelledFenceWorker(
		t,
		driver,
		execution,
	)

	oldExecution :=
		execution

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			fenceIntegrationOwner,
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution != nil {
		t.Fatal(
			"execution not cleared after successful fence ACK",
		)
	}

	if cp.ackCount.Load() !=
		1 {

		t.Fatalf(
			"ack_count=%d want=1",
			cp.ackCount.Load(),
		)
	}

	if !cp.acknowledged() {
		t.Fatal(
			"Control Plane did not commit fence acknowledgement",
		)
	}

	if oldExecution.FenceProofToken != "" {
		t.Fatal(
			"RAM fence proof survived successful ACK",
		)
	}

	if cp.terminalCount.Load() !=
		0 {

		t.Fatal(
			"fenced execution emitted a terminal deployment report",
		)
	}

	if localState.AppliedGeneration !=
		14 {

		t.Fatalf(
			"applied_generation=%d want=14",
			localState.AppliedGeneration,
		)
	}
}

func TestFenceIntegrationRenew409BeforeFenceAssignment(
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
		&fenceIntegrationCP{
			deploymentStatus: "pending",

			nodeApplied: 14,

			renewConflict: true,
		}

	server :=
		newFenceIntegrationServer(
			t,
			cp,
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)

	defer cancel()

	var execution *leasedExecution

	startBlockingFenceExecution(
		t,
		ctx,
		client,
		driver,
		statePath,
		&localState,
		&execution,
	)

	// Fence exists on CP, but assignment deliberately does not
	// reveal it yet.
	cp.requestFence(
		false,
	)

	// Force renewal before the next assignment poll.
	execution.NextRenewAt =
		time.Now().
			Add(
				-time.Second,
			).
			UTC()

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			fenceIntegrationOwner,
			&execution,
		)

	// Current supervisor may return a health result instead of
	// propagating the original 409.
	if err != nil {
		status, ok :=
			agent.HTTPErrorStatus(
				err,
			)

		if ok &&
			status !=
				http.StatusConflict {

			t.Fatalf(
				"unexpected HTTP status=%d",
				status,
			)
		}
	}

	if execution == nil {
		t.Fatal(
			"renew-rejected execution disappeared before fencing",
		)
	}

	if !execution.LeaseLost {
		t.Fatal(
			"renew 409 did not revoke authority",
		)
	}

	if execution.LeaseToken != "" {
		t.Fatal(
			"authority token survived renew 409",
		)
	}

	if execution.FenceProofToken !=
		fenceIntegrationProof {

		t.Fatal(
			"renew 409 destroyed RAM fencing proof",
		)
	}

	if execution.FenceRequest != nil {
		t.Fatal(
			"hidden fence was observed before assignment revealed it",
		)
	}

	if cp.renewCount.Load() !=
		1 {

		t.Fatalf(
			"renew_count=%d want=1",
			cp.renewCount.Load(),
		)
	}

	consumeCancelledFenceWorker(
		t,
		driver,
		execution,
	)

	cp.revealFence()

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			fenceIntegrationOwner,
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution != nil {
		t.Fatal(
			"execution not cleared after delayed fence ACK",
		)
	}

	if cp.ackCount.Load() !=
		1 {

		t.Fatalf(
			"ack_count=%d want=1",
			cp.ackCount.Load(),
		)
	}

	if !cp.acknowledged() {
		t.Fatal(
			"delayed fence was not acknowledged",
		)
	}

	if cp.claimCount.Load() !=
		1 {

		t.Fatalf(
			"claim_count=%d want=1",
			cp.claimCount.Load(),
		)
	}

	if driver.reconcileCount.Load() !=
		1 {

		t.Fatalf(
			"reconcile_count=%d want=1",
			driver.reconcileCount.Load(),
		)
	}

	if cp.terminalCount.Load() !=
		0 {

		t.Fatal(
			"renew-rejected fenced execution emitted terminal report",
		)
	}

	if localState.AppliedGeneration !=
		14 {

		t.Fatalf(
			"applied_generation=%d want=14",
			localState.AppliedGeneration,
		)
	}
}

func TestFenceIntegrationLostACKResponseRetriesFromRAM(
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
		&fenceIntegrationCP{
			deploymentStatus: "pending",

			nodeApplied: 14,

			loseFirstACKResponse: true,
		}

	server :=
		newFenceIntegrationServer(
			t,
			cp,
		)

	defer server.Close()

	client :=
		agent.NewClient(
			server.URL,
		)

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)

	defer cancel()

	var execution *leasedExecution

	startBlockingFenceExecution(
		t,
		ctx,
		client,
		driver,
		statePath,
		&localState,
		&execution,
	)

	execution.NextRenewAt =
		time.Now().
			Add(
				time.Hour,
			).
			UTC()

	cp.requestFence(
		true,
	)

	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			fenceIntegrationOwner,
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	consumeCancelledFenceWorker(
		t,
		driver,
		execution,
	)

	assignmentsBeforeACK :=
		cp.assignmentCount.Load()

	// First ACK commits at CP but its HTTP response is lost.
	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			fenceIntegrationOwner,
			&execution,
		)

	if err == nil {
		t.Fatal(
			"expected simulated lost ACK response error",
		)
	}

	if execution == nil {
		t.Fatal(
			"execution was cleared despite lost ACK response",
		)
	}

	if execution.FenceRequest == nil {
		t.Fatal(
			"observed fence request was lost after ACK response failure",
		)
	}

	if execution.FenceProofToken !=
		fenceIntegrationProof {

		t.Fatal(
			"RAM proof was destroyed before ACK success was observed",
		)
	}

	if !cp.acknowledged() {
		t.Fatal(
			"fake Control Plane did not commit first ACK",
		)
	}

	if cp.ackCount.Load() !=
		1 {

		t.Fatalf(
			"ack_count=%d want=1 after lost response",
			cp.ackCount.Load(),
		)
	}

	// CP no longer exposes the request in assignment because
	// the first ACK already committed. The retained RAM request
	// must make the retry independent of another assignment GET.
	err =
		leaseSupervisorTick(
			ctx,
			client,
			driver,
			statePath,
			agent.SystemInfo{},
			&localState,
			fenceIntegrationOwner,
			&execution,
		)

	if err != nil {
		t.Fatal(err)
	}

	if execution != nil {
		t.Fatal(
			"execution not cleared after idempotent ACK retry",
		)
	}

	if cp.ackCount.Load() !=
		2 {

		t.Fatalf(
			"ack_count=%d want=2",
			cp.ackCount.Load(),
		)
	}

	if cp.assignmentCount.Load() !=
		assignmentsBeforeACK {

		t.Fatalf(
			"ACK retry unexpectedly depended on assignment: before=%d after=%d",
			assignmentsBeforeACK,
			cp.assignmentCount.Load(),
		)
	}

	if cp.terminalCount.Load() !=
		0 {

		t.Fatal(
			"fenced execution emitted forbidden terminal report",
		)
	}

	if localState.AppliedGeneration !=
		14 {

		t.Fatalf(
			"applied_generation=%d want=14",
			localState.AppliedGeneration,
		)
	}
}
