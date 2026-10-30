package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/core"
	"vpn-platform/internal/core/xray"
	"vpn-platform/internal/model"
)

// Candidate source; publication requires the installer pin and native lifecycle
// proofs. New protocol runtimes remain isolated until publication is approved.
const agentVersion = "0.2.39"

var collectNodeMetrics = agent.CollectMetrics
var collectClientTraffic = agent.CollectClientTraffic

func main() {
	if handled, err := runLocalCommand(os.Args[1:]); handled {
		if err != nil {
			log.Print("local agent command failed")
			os.Exit(1)
		}
		return
	}
	if err := runAgent(); err != nil {
		log.Print("node agent stopped: startup or runtime unavailable")
		os.Exit(1)
	}
}

// Return through cleanup rather than log.Fatal: local ownership is released
// only after workers stop, final traffic is captured and Hysteria is closed.
func runAgent() (result error) {
	controlPlane := strings.TrimSpace(os.Getenv("VPN_CONTROL_PLANE"))
	if controlPlane == "" {
		return errSelectedRuntime
	}
	bootstrapToken := strings.TrimSpace(os.Getenv("VPN_BOOTSTRAP_TOKEN"))
	baseDir := env("VPN_AGENT_DATA", "/var/lib/vpn-platform")
	statePath := env("VPN_AGENT_STATE", filepath.Join(baseDir, "agent", "state.json"))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return err
	}
	release, err := core.AcquireNodeOwnership(ctx, baseDir)
	if err != nil {
		return err
	}
	defer release()
	selected, err := core.ReadRuntimeSelection(baseDir, env("VPN_RUNTIME_CORE", ""), agentVersion)
	if err != nil {
		return err
	}
	if selected.Core == "hysteria2" && statePath != filepath.Join(baseDir, "agent", "state.json") {
		return errSelectedRuntime
	}
	if _, err = core.SelectRuntimeCore(ctx, baseDir, selected.Core, agentVersion); err != nil {
		return err
	}
	client := agent.NewClient(controlPlane)
	system := agent.DetectSystem()
	localState, err := agent.LoadState(statePath)
	if err != nil {
		return err
	}
	if localState.AgentToken == "" {
		if bootstrapToken == "" {
			return errSelectedRuntime
		}
		registration, err := client.RegisterForRuntime(ctx, bootstrapToken, agentVersion, system, selected.Core)
		if err != nil {
			return err
		}
		localState.NodeID = registration.NodeID
		localState.TenantID = registration.TenantID
		localState.AgentToken = registration.AgentToken
		if err := agent.SaveState(statePath, localState); err != nil {
			return err
		}
	}
	runtime, err := openAgentRuntime(ctx, selected.Core, baseDir, statePath, localState, client)
	if err != nil {
		return err
	}
	defer func() {
		if err := runtime.close(); err != nil && result == nil {
			result = err
		}
	}()
	driver := runtime.driver
	// Dedicated durable delivery is the only traffic path for this agent.
	collectClientTraffic = func() *model.ClientTrafficSnapshot { return nil }
	if trafficWorker := runtime.traffic; trafficWorker != nil {
		trafficCtx, cancelTraffic := context.WithCancel(ctx)
		trafficDone := make(chan struct{})
		go func() { defer close(trafficDone); trafficWorker.Run(trafficCtx) }()
		defer func() {
			cancelTraffic()
			<-trafficDone
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			trafficWorker.BeforeStop(flushCtx)
		}()
	}
	ownerInstanceID, err := agent.NewProcessInstanceID()
	if err != nil {
		return err
	}
	if err := validateCertificateWorkerConfig(localState.AgentToken, ownerInstanceID, baseDir); err != nil {
		return err
	}
	log.Printf("VPN Platform Node Agent %s started node=%s core=%s", agentVersion, localState.NodeID, selected.Core)
	workerCtx, cancelWorker := context.WithCancel(ctx)
	workerDone := make(chan struct{})
	workerAgentToken := localState.AgentToken
	go func() {
		defer close(workerDone)
		runCertificateWorker(workerCtx, client, workerAgentToken, ownerInstanceID, baseDir, runtime.refresh)
	}()
	rebootWorkerDone := make(chan struct{})
	go func() {
		defer close(rebootWorkerDone)
		runNodeRebootWorker(workerCtx, client, workerAgentToken, ownerInstanceID)
	}()
	defer func() { cancelWorker(); <-workerDone; <-rebootWorkerDone }()
	runLeaseSupervisor(ctx, client, driver, statePath, system, &localState, ownerInstanceID)
	return nil
}
func cycle(
	ctx context.Context,
	client *agent.Client,
	driver *xray.Driver,
	statePath string,
	system agent.SystemInfo,
	localState *agent.LocalState,
) error {

	desired, exists, err :=
		client.DesiredState(
			ctx,
			localState.AgentToken,
		)

	if err != nil {
		return err
	}

	if !exists {
		return sendHealth(
			ctx,
			client,
			driver,
			system,
			localState,
			true,
			"agent online; waiting for desired state",
		)
	}

	if desired.Generation >
		localState.AppliedGeneration {

		if generationAwaitingRecovery(
			desired.Generation,
			localState.AppliedGeneration,
			localState.FailedGeneration,
		) {
			healthy, _ :=
				driver.Health()

			return sendHealth(
				ctx,
				client,
				driver,
				system,
				localState,
				healthy,
				fmt.Sprintf(
					"generation %d terminal after failed deployment; awaiting recovery decision",
					desired.Generation,
				),
			)
		}

		log.Printf(
			"reconcile generation=%d core=%s version=%s",
			desired.Generation,
			desired.Core.Type,
			desired.Core.Version,
		)

		if statusErr :=
			sendDeploymentStatus(
				ctx,
				client,
				localState,
				desired.Generation,
				"applying",
				"",
				"",
			); statusErr != nil {

			log.Printf(
				"deployment applying status error: %v",
				statusErr,
			)
		}

		if err :=
			driver.Reconcile(
				ctx,
				desired,
			); err != nil {

			localState.FailedGeneration =
				desired.Generation

			// Legacy retry fields remain in the state format for
			// backwards compatibility, but autonomous retries are
			// intentionally disabled. Recovery belongs to the
			// Control Plane and requires a new generation.
			localState.FailureCount = 0
			localState.NextRetryUnix = 0

			if saveErr :=
				agent.SaveState(
					statePath,
					*localState,
				); saveErr != nil {

				return saveErr
			}

			healthy, _ :=
				driver.Health()

			deploymentStatus :=
				"failed"

			appliedCoreVersion :=
				""

			if healthy {
				deploymentStatus =
					"rolled_back"

				appliedCoreVersion =
					driver.CurrentVersion()
			}

			message :=
				fmt.Sprintf(
					"generation %d failed: %v; terminal deployment; awaiting recovery decision",
					desired.Generation,
					err,
				)

			if statusErr :=
				sendDeploymentStatus(
					ctx,
					client,
					localState,
					desired.Generation,
					deploymentStatus,
					appliedCoreVersion,
					err.Error(),
				); statusErr != nil {

				log.Printf(
					"deployment failure status error: %v",
					statusErr,
				)
			}

			_ = sendHealth(
				ctx,
				client,
				driver,
				system,
				localState,
				healthy,
				message,
			)

			return fmt.Errorf(
				"%s",
				message,
			)
		}

		localState.AppliedGeneration =
			desired.Generation

		localState.FailedGeneration = 0
		localState.FailureCount = 0
		localState.NextRetryUnix = 0

		if err :=
			agent.SaveState(
				statePath,
				*localState,
			); err != nil {

			return err
		}

		log.Printf(
			"generation=%d applied successfully",
			desired.Generation,
		)

		if statusErr :=
			sendDeploymentStatus(
				ctx,
				client,
				localState,
				desired.Generation,
				"healthy",
				driver.CurrentVersion(),
				"",
			); statusErr != nil {

			log.Printf(
				"deployment healthy status error: %v",
				statusErr,
			)
		}
	}

	healthy, healthErr :=
		driver.Health()

	message := "healthy"

	if healthErr != nil {
		healthy = false
		message = healthErr.Error()
	}

	return sendHealth(
		ctx,
		client,
		driver,
		system,
		localState,
		healthy,
		message,
	)
}

func sendHealth(
	ctx context.Context,
	client *agent.Client,
	driver *xray.Driver,
	system agent.SystemInfo,
	localState *agent.LocalState,
	healthy bool,
	message string,
) error {

	return client.Health(
		ctx,
		localState.AgentToken,
		model.HealthReport{
			RuntimeRecoveryInfo: runtimeRecoveryInfo(driver),
			Healthy:             healthy,

			AppliedGeneration: localState.AppliedGeneration,

			Core: "xray",

			CoreVersion: driver.CurrentVersion(),

			Message: message,

			CheckedAt: time.Now().UTC(),

			AgentVersion: agentVersion,

			OSName: system.OSName,

			OSVersion: system.OSVersion,

			Architecture:    system.Architecture,
			Metrics:         collectNodeMetrics(),
			TrafficSnapshot: collectClientTraffic(),
		},
	)
}

func sendDeploymentStatus(
	ctx context.Context,
	client *agent.Client,
	localState *agent.LocalState,
	generation int64,
	status string,
	appliedCoreVersion string,
	errorMessage string,
) error {

	return client.DeploymentStatus(
		ctx,
		localState.AgentToken,
		model.DeploymentReport{
			Generation: generation,

			Status: status,

			AppliedCoreVersion: appliedCoreVersion,

			ErrorMessage: errorMessage,

			ReportedAt: time.Now().UTC(),
		},
	)
}

func retryDelay(
	failureCount int,
) time.Duration {

	switch {
	case failureCount <= 1:
		return 10 * time.Second

	case failureCount == 2:
		return 30 * time.Second

	case failureCount == 3:
		return time.Minute

	case failureCount == 4:
		return 5 * time.Minute

	case failureCount == 5:
		return 10 * time.Minute

	default:
		return 30 * time.Minute
	}
}

func mustEnv(
	name string,
) string {

	value := strings.TrimSpace(
		os.Getenv(name),
	)

	if value == "" {
		log.Fatalf(
			"%s required",
			name,
		)
	}

	return value
}

func env(
	name string,
	fallback string,
) string {

	value := strings.TrimSpace(
		os.Getenv(name),
	)

	if value == "" {
		return fallback
	}

	return value
}

func generationAwaitingRecovery(
	desiredGeneration int64,
	appliedGeneration int64,
	failedGeneration int64,
) bool {
	return desiredGeneration > appliedGeneration &&
		failedGeneration == desiredGeneration
}
