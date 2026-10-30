package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/recovery"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
	upstreamxray "vpn-platform/internal/upstream/xray"
)

type application struct {
	store      *store.Postgres
	adminToken string
}

func main() {
	ctx := context.Background()

	databaseURL := mustEnv("DATABASE_URL")
	adminToken := mustEnv("ADMIN_TOKEN")

	listenAddr := env(
		"LISTEN_ADDR",
		"127.0.0.1:8080",
	)

	db, err := store.NewPostgres(
		ctx,
		databaseURL,
	)
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	app := &application{
		store:      db,
		adminToken: adminToken,
	}

	mux := http.NewServeMux()
	app.registerAgentFleetRoutes(mux)
	mux.HandleFunc("POST /api/v1/nodes/{id}/xray-update", app.requireAdmin(app.startReviewedXrayUpdate))
	go app.runAgentFleetController(ctx)
	app.registerAdminAccountRoutes(mux)
	app.registerAdminSessionRoutes(mux)
	app.registerAdminMFARoutes(mux)
	app.registerAccessPlanRoutes(mux)
	app.registerCascadeRoutes(mux)
	app.registerCertificateManagementRoutes(mux)
	app.registerNodeRebootRoutes(mux)
	app.registerTLSServiceRoutes(mux)
	app.registerTenantAPIRoutes(mux)
	app.registerBotBridgeRoutes(mux)
	app.registerBillingRoutes(mux)
	app.registerTenantBrandingRoutes(mux)
	app.registerAutoProfileRoutes(mux)
	app.registerMonitoringRoutes(mux)
	app.registerWebhookRoutes(mux)
	app.registerAuditRoutes(mux)
	app.registerResellerRoutes(mux)
	app.registerTenantLimitRoutes(mux)
	app.registerMetricsRoutes(mux)
	app.registerVPNClientUsageRoutes(mux)
	app.registerDeviceRoutes(mux)
	app.registerAgentCapabilityRoutes(mux)
	app.registerHysteriaOnboardingRoutes(mux)
	app.registerXrayOnboardingRoutes(mux)
	app.registerOpenVPNOnboardingRoutes(mux)
	app.registerPPTPOnboardingRoutes(mux)
	app.registerRemnawaveRoutes(mux)
	app.registerImportedSubscriptionRoutes(mux)
	app.registerImportedPageRoutes(mux)
	mux.HandleFunc("DELETE /api/v1/vpn-clients/{id}", app.requireAdmin(app.deleteVPNClient))
	app.registerNativeWireGuardOnboardingRoutes(mux)
	app.registerAmneziaWGRoutes(mux)
	mux.HandleFunc("GET /api/v1/operations/status", app.requireAdmin(app.getOperationsStatus))
	mux.HandleFunc("POST /api/v1/agent/backup-status", app.requireAgent(app.agentBackupStatus))
	mux.HandleFunc("GET /api/v1/agent/status", app.requireAgent(app.agentSelfStatus))

	mux.HandleFunc(
		"GET /healthz",
		app.healthz,
	)

	mux.HandleFunc(
		"GET /api/v1/tenants",
		app.requireAdmin(app.listTenants),
	)

	mux.HandleFunc(
		"POST /api/v1/tenants",
		app.requireAdmin(app.createTenant),
	)

	mux.HandleFunc(
		"POST /api/v1/tenants/{id}/vpn-clients",
		app.requireAdmin(app.createVPNClient),
	)

	mux.HandleFunc(
		"GET /api/v1/tenants/{id}/vpn-clients",
		app.requireAdmin(app.listVPNClients),
	)

	mux.HandleFunc(
		"GET /api/v1/vpn-clients/{id}",
		app.requireAdmin(app.getVPNClient),
	)

	mux.HandleFunc(
		"GET /api/v1/vpn-clients/{id}/connections",
		app.requireAdmin(app.listVPNClientConnections),
	)

	mux.HandleFunc(
		"GET /api/v1/vpn-clients/{id}/services",
		app.requireAdmin(app.listVPNClientDirectServices),
	)
	mux.HandleFunc(
		"PATCH /api/v1/vpn-clients/{id}",
		app.requireAdmin(app.updateVPNClient),
	)

	mux.HandleFunc(
		"POST /api/v1/vpn-clients/{id}/disable",
		app.requireAdmin(app.disableVPNClient),
	)

	mux.HandleFunc(
		"POST /api/v1/vpn-clients/{id}/enable",
		app.requireAdmin(app.enableVPNClient),
	)

	mux.HandleFunc(
		"POST /api/v1/vpn-clients/{id}/subscription",
		app.requireAdmin(app.createVPNClientSubscription),
	)
	mux.HandleFunc(
		"GET /api/v1/vpn-clients/{id}/subscription",
		app.requireAdmin(app.getVPNClientSubscription),
	)
	mux.HandleFunc(
		"POST /api/v1/vpn-clients/{id}/subscription/rotate",
		app.requireAdmin(app.rotateVPNClientSubscription),
	)
	mux.HandleFunc(
		"GET /sub/{token}",
		app.getPublicVPNSubscription,
	)
	mux.HandleFunc("GET /sub/{token}/{format}", app.getPublicVPNSubscription)
	mux.HandleFunc("GET /sub/{token}/info", app.getPublicSubscriptionInfo)
	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/certificates",
		app.requireAdmin(app.createNodeCertificate),
	)
	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/certificates",
		app.requireAdmin(app.listNodeCertificates),
	)
	mux.HandleFunc(
		"GET /api/v1/certificates/{id}",
		app.requireAdmin(app.getNodeCertificate),
	)
	mux.HandleFunc(
		"POST /api/v1/certificates/{id}/issue",
		app.requireAdmin(app.issueCertificate),
	)
	mux.HandleFunc(
		"POST /api/v1/certificates/{id}/renew",
		app.requireAdmin(app.renewCertificate),
	)

	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/vpn-services",
		app.requireAdmin(app.createVPNService),
	)

	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/vpn-services",
		app.requireAdmin(app.listVPNServices),
	)

	mux.HandleFunc(
		"GET /api/v1/vpn-services/{id}",
		app.requireAdmin(app.getVPNService),
	)
	mux.HandleFunc(
		"PATCH /api/v1/vpn-services/{id}",
		app.requireAdmin(app.updateVPNServicePublicEndpoint),
	)
	mux.HandleFunc("PUT /api/v1/vpn-services/{id}/subscription-name", app.requireAdmin(app.updateVPNServiceSubscriptionName))

	mux.HandleFunc(
		"GET /api/v1/vpn-services/{id}/reality",
		app.requireAdmin(app.getVPNServiceReality),
	)
	mux.HandleFunc(
		"POST /api/v1/vpn-services/{id}/reality",
		app.requireAdmin(app.configureVPNServiceReality),
	)

	mux.HandleFunc(
		"PATCH /api/v1/vpn-services/{id}/reality",
		app.requireAdmin(app.updateVPNServiceReality),
	)
	mux.HandleFunc(
		"POST /api/v1/vpn-services/{id}/enable",
		app.requireAdmin(app.enableVPNService),
	)
	mux.HandleFunc(
		"POST /api/v1/vpn-services/{id}/disable",
		app.requireAdmin(app.disableVPNService),
	)
	mux.HandleFunc("DELETE /api/v1/vpn-services/{id}", app.requireAdmin(app.deleteVPNService))

	mux.HandleFunc(
		"POST /api/v1/vpn-services/{id}/clients/{client_id}/provision",
		app.requireAdmin(app.provisionVPNClient),
	)

	mux.HandleFunc(
		"POST /api/v1/vpn-services/{id}/clients/{client_id}",
		app.requireAdmin(app.attachVPNClientToService),
	)

	mux.HandleFunc(
		"DELETE /api/v1/vpn-services/{id}/clients/{client_id}",
		app.requireAdmin(app.detachVPNClientFromService),
	)

	mux.HandleFunc(
		"POST /api/v1/nodes",
		app.requireAdmin(app.createNode),
	)

	mux.HandleFunc(
		"GET /api/v1/nodes",
		app.requireAdmin(app.listNodes),
	)
	mux.HandleFunc("PATCH /api/v1/nodes/{id}", app.requireAdmin(app.renameNode))
	mux.HandleFunc("DELETE /api/v1/nodes/{id}", app.requireAdmin(app.deleteNode))
	mux.HandleFunc(
		"GET /api/v1/nodes/{id}",
		app.requireAdmin(app.getNode),
	)
	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/lifecycle",
		app.requireAdmin(app.nodeLifecycle),
	)
	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/diagnostics",
		app.requireAdmin(app.nodeDiagnostics),
	)
	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/bootstrap-token/rotate",
		app.requireAdmin(app.rotateNodeBootstrapToken),
	)
	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/runtime-status",
		app.requireAdmin(app.nodeRuntimeStatus),
	)

	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/deployments/{generation}/recovery-attempts",
		app.requireAdmin(app.createRecoveryAttempt),
	)

	mux.HandleFunc(
		"GET /api/v1/recovery-attempts/{id}",
		app.requireAdmin(app.getRecoveryAttempt),
	)

	mux.HandleFunc(
		"POST /api/v1/recovery-attempts/{id}/approve",
		app.requireAdmin(app.approveRecoveryAttempt),
	)

	mux.HandleFunc(
		"POST /api/v1/recovery-attempts/{id}/execute",
		app.requireAdmin(app.executeRecoveryAttempt),
	)

	mux.HandleFunc(
		"POST /api/v1/recovery-attempts/{id}/cancel",
		app.requireAdmin(app.cancelRecoveryAttempt),
	)

	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/deployments/{generation}/recovery-evaluation",
		app.requireAdmin(app.deploymentRecoveryEvaluation),
	)

	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/deployments",
		app.requireAdmin(app.listNodeDeployments),
	)

	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/core-update-status",
		app.requireAdmin(app.coreUpdateStatus),
	)

	mux.HandleFunc(
		"GET /api/v1/nodes/{id}/core-update-evaluate",
		app.requireAdmin(app.coreUpdateEvaluate),
	)

	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/rollout-plans",
		app.requireAdmin(app.createRolloutPlan),
	)

	mux.HandleFunc(
		"GET /api/v1/rollout-plans/{id}",
		app.requireAdmin(app.getRolloutPlan),
	)

	mux.HandleFunc(
		"POST /api/v1/rollout-plans/{id}/approve",
		app.requireAdmin(app.approveRolloutPlan),
	)

	mux.HandleFunc(
		"POST /api/v1/rollout-plans/{id}/cancel",
		app.requireAdmin(app.cancelRolloutPlan),
	)

	mux.HandleFunc(
		"POST /api/v1/rollout-plans/{id}/execute",
		app.requireAdmin(app.executeRolloutPlan),
	)

	mux.HandleFunc(
		"PUT /api/v1/nodes/{id}/core-update-policy",
		app.requireAdmin(app.setCoreUpdatePolicy),
	)

	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/desired-state",
		app.requireAdmin(app.setDesiredState),
	)

	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/rebuild-desired-state",
		app.requireAdmin(app.rebuildNodeDesiredState),
	)

	mux.HandleFunc(
		"GET /api/v1/core-releases",
		app.requireAdmin(app.listCoreReleases),
	)

	mux.HandleFunc(
		"POST /api/v1/core-releases",
		app.requireAdmin(app.createCoreRelease),
	)

	mux.HandleFunc(
		"POST /api/v1/core-releases/import/xray/latest",
		app.requireAdmin(app.importLatestXrayRelease),
	)

	mux.HandleFunc(
		"POST /api/v1/core-releases/import/xray/{version}",
		app.requireAdmin(app.importXrayReleaseByVersion),
	)

	mux.HandleFunc(
		"POST /api/v1/core-releases/{id}/approve",
		app.requireAdmin(app.approveCoreRelease),
	)

	mux.HandleFunc(
		"POST /api/v1/core-releases/{id}/promote",
		app.requireAdmin(app.promoteCoreRelease),
	)

	mux.HandleFunc(
		"POST /api/v1/core-releases/{id}/revoke",
		app.requireAdmin(app.revokeCoreRelease),
	)

	mux.HandleFunc(
		"POST /api/v1/nodes/{id}/deployments/{generation}/fence",
		app.requireAdmin(app.createExecutionFenceRequest),
	)

	mux.HandleFunc(
		"POST /api/v1/agent/register",
		app.registerAgent,
	)

	mux.HandleFunc(
		"GET /api/v1/agent/desired-state",
		app.requireAgent(app.agentDesiredState),
	)

	mux.HandleFunc(
		"GET /api/v1/agent/assignment",
		app.requireAgent(app.agentAssignment),
	)

	mux.HandleFunc(
		"POST /api/v1/agent/execution/claim",
		app.requireAgent(app.agentExecutionClaim),
	)

	mux.HandleFunc(
		"POST /api/v1/agent/execution/renew",
		app.requireAgent(app.agentExecutionRenew),
	)

	mux.HandleFunc(
		"POST /api/v1/agent/execution/fence-ack",
		app.requireAgent(app.agentExecutionFenceAck),
	)

	mux.HandleFunc(
		"POST /api/v1/agent/health",
		app.requireAgent(app.agentHealth),
	)
	mux.HandleFunc("POST /api/v1/agent/traffic", app.requireAgent(app.receiveTrafficDelivery))

	mux.HandleFunc(
		"POST /api/v1/agent/reality-material",
		app.requireAgent(app.agentRealityMaterial),
	)
	mux.HandleFunc(
		"POST /api/v1/agent/certificate-jobs/claim",
		app.requireAgent(app.agentCertificateJobClaim),
	)
	mux.HandleFunc(
		"POST /api/v1/agent/certificate-jobs/renew",
		app.requireAgent(app.agentCertificateJobRenew),
	)
	mux.HandleFunc(
		"POST /api/v1/agent/certificate-jobs/result",
		app.requireAgent(app.agentCertificateJobResult),
	)

	mux.HandleFunc(
		"POST /api/v1/agent/deployment-status",
		app.requireAgent(app.agentDeploymentStatus),
	)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	log.Printf(
		"VPN Platform Control Plane listening on %s",
		listenAddr,
	)

	log.Fatal(server.ListenAndServe())
}

func (a *application) healthz(
	w http.ResponseWriter,
	r *http.Request,
) {
	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"status":  "ok",
			"service": "vpn-platform-control-plane",
			"version": controlPlaneVersion,
		},
	)
}

func (a *application) listTenants(
	w http.ResponseWriter,
	r *http.Request,
) {
	tenants, err :=
		a.store.ListTenants(
			r.Context(),
		)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"tenants": tenants,
		},
	)
}

func (a *application) createTenant(
	w http.ResponseWriter,
	r *http.Request,
) {
	var input struct {
		Name string `json:"name"`
	}

	if err := readJSON(r, &input); err != nil {
		writeError(w, 400, err.Error())
		return
	}

	input.Name = strings.TrimSpace(input.Name)

	if input.Name == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"name is required",
		)
		return
	}

	tenant, err := a.store.CreateTenant(
		r.Context(),
		input.Name,
	)

	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		tenant,
	)
}

func (a *application) createNode(
	w http.ResponseWriter,
	r *http.Request,
) {
	var input struct {
		TenantID    string `json:"tenant_id"`
		RuntimeCore string `json:"runtime_core"`
		Name        string `json:"name"`
	}

	if err := readJSON(r, &input); err != nil {
		writeError(w, 400, err.Error())
		return
	}

	input.TenantID =
		strings.TrimSpace(input.TenantID)

	input.Name =
		strings.TrimSpace(input.Name)

	if input.TenantID == "" ||
		input.Name == "" {

		writeError(
			w,
			http.StatusBadRequest,
			"tenant_id and name are required",
		)

		return
	}

	input.RuntimeCore = strings.TrimSpace(input.RuntimeCore)
	if input.RuntimeCore == "" {
		input.RuntimeCore = "xray"
	}
	if !model.ValidRuntimeCore(input.RuntimeCore) {
		writeError(w, 400, "unsupported node runtime")
		return
	}
	bootstrapToken, err :=
		security.NewToken(32)

	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	node, err := a.store.CreateNodeForRuntime(
		r.Context(),
		input.TenantID,
		input.Name,
		security.HashToken(
			bootstrapToken,
		),
		input.RuntimeCore,
	)

	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		map[string]any{
			"node": node,

			"bootstrap_token": bootstrapToken,

			"bootstrap_token_note": "shown once; store securely",
		},
	)
}

func (a *application) listNodes(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodes, err :=
		a.store.ListNodesByDeletion(
			r.Context(), r.URL.Query().Get("deleted") == "true",
		)

	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"nodes": nodes,
		},
	)
}

func (a *application) deploymentRecoveryEvaluation(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	generationRaw :=
		strings.TrimSpace(
			r.PathValue(
				"generation",
			),
		)

	generation, err :=
		strconv.ParseInt(
			generationRaw,
			10,
			64,
		)

	if err != nil ||
		generation < 1 {

		writeError(
			w,
			http.StatusBadRequest,
			"valid generation is required",
		)
		return
	}

	evaluatedAt :=
		time.Now().UTC()

	facts, err :=
		a.store.DeploymentRecoveryFacts(
			r.Context(),
			nodeID,
			generation,
			evaluatedAt,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"deployment not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	evaluation :=
		recovery.Evaluate(
			facts,
			evaluatedAt,
		)

	writeJSON(
		w,
		http.StatusOK,
		evaluation,
	)
}

func (a *application) listNodeDeployments(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	observedAt :=
		time.Now().UTC()

	deployments, err :=
		a.store.ListDeploymentObservations(
			r.Context(),
			nodeID,
			observedAt,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"node_id":     nodeID,
			"observed_at": observedAt,
			"deployments": deployments,
		},
	)
}

func (a *application) importXrayReleaseByVersion(
	w http.ResponseWriter,
	r *http.Request,
) {
	version :=
		strings.TrimSpace(
			r.PathValue("version"),
		)

	if version == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"version is required",
		)
		return
	}

	client :=
		upstreamxray.NewClient()

	upstreamRelease, err :=
		client.LinuxAMD64ByVersion(
			r.Context(),
			version,
		)

	if err != nil {
		writeError(
			w,
			http.StatusBadGateway,
			err.Error(),
		)
		return
	}

	metadata := map[string]any{
		"source": "github",

		"repository": "XTLS/Xray-core",

		"github_release_id": upstreamRelease.ReleaseID,

		"github_asset_id": upstreamRelease.AssetID,

		"asset_name": upstreamRelease.AssetName,

		"published_at": upstreamRelease.PublishedAt,

		"importer": "vpn-platform-control-plane",

		"import_mode": "explicit_version",
	}

	metadataRaw, err :=
		json.Marshal(metadata)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	release, created, err :=
		a.store.ImportCoreRelease(
			r.Context(),
			model.CoreReleaseRecord{
				Type: "xray",

				Version: upstreamRelease.Version,

				OS: "linux",

				Architecture: "amd64",

				DownloadURL: upstreamRelease.DownloadURL,

				SHA256: upstreamRelease.SHA256,

				Channel: "testing",

				UpstreamPrerelease: upstreamRelease.UpstreamPrerelease,
			},
			string(metadataRaw),
		)

	if errors.Is(
		err,
		store.ErrCoreReleaseIntegrityConflict,
	) {
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	status :=
		"already_present"

	httpStatus :=
		http.StatusOK

	if created {
		status = "imported"
		httpStatus =
			http.StatusCreated
	}

	writeJSON(
		w,
		httpStatus,
		map[string]any{
			"status": status,

			"created": created,

			"release": release,
		},
	)
}

func (a *application) importLatestXrayRelease(
	w http.ResponseWriter,
	r *http.Request,
) {
	client :=
		upstreamxray.NewClient()

	upstreamRelease, err :=
		client.LatestLinuxAMD64(
			r.Context(),
		)

	if err != nil {
		writeError(
			w,
			http.StatusBadGateway,
			err.Error(),
		)
		return
	}

	metadata := map[string]any{
		"source": "github",

		"repository": "XTLS/Xray-core",

		"github_release_id": upstreamRelease.ReleaseID,

		"github_asset_id": upstreamRelease.AssetID,

		"asset_name": upstreamRelease.AssetName,

		"published_at": upstreamRelease.PublishedAt,

		"importer": "vpn-platform-control-plane",
	}

	metadataRaw, err :=
		json.Marshal(metadata)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	release, created, err :=
		a.store.ImportCoreRelease(
			r.Context(),
			model.CoreReleaseRecord{
				Type: "xray",

				Version: upstreamRelease.Version,

				OS: "linux",

				Architecture: "amd64",

				DownloadURL: upstreamRelease.DownloadURL,

				SHA256: upstreamRelease.SHA256,

				Channel: "testing",

				UpstreamPrerelease: upstreamRelease.UpstreamPrerelease,
			},
			string(metadataRaw),
		)

	if errors.Is(
		err,
		store.ErrCoreReleaseIntegrityConflict,
	) {
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	status :=
		"already_present"

	httpStatus :=
		http.StatusOK

	if created {
		status = "imported"
		httpStatus =
			http.StatusCreated
	}

	writeJSON(
		w,
		httpStatus,
		map[string]any{
			"status": status,

			"created": created,

			"release": release,
		},
	)
}

func (a *application) listCoreReleases(
	w http.ResponseWriter,
	r *http.Request,
) {
	releases, err :=
		a.store.ListCoreReleases(
			r.Context(),
		)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"releases": releases,
		},
	)
}

func (a *application) createCoreRelease(
	w http.ResponseWriter,
	r *http.Request,
) {
	var input struct {
		Type               string `json:"type"`
		Version            string `json:"version"`
		OS                 string `json:"os"`
		Architecture       string `json:"architecture"`
		DownloadURL        string `json:"download_url"`
		SHA256             string `json:"sha256"`
		Channel            string `json:"channel"`
		UpstreamPrerelease bool   `json:"upstream_prerelease"`
	}

	if err := readJSON(
		r,
		&input,
	); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.Type =
		strings.ToLower(
			strings.TrimSpace(input.Type),
		)

	input.Version =
		strings.TrimSpace(input.Version)

	input.OS =
		strings.ToLower(
			strings.TrimSpace(input.OS),
		)

	input.Architecture =
		strings.ToLower(
			strings.TrimSpace(input.Architecture),
		)

	input.DownloadURL =
		strings.TrimSpace(input.DownloadURL)

	input.SHA256 =
		strings.ToLower(
			strings.TrimSpace(input.SHA256),
		)

	input.Channel =
		strings.ToLower(
			strings.TrimSpace(input.Channel),
		)

	if input.Channel == "" {
		input.Channel = "testing"
	}

	if input.Type == "" ||
		input.Version == "" ||
		input.OS == "" ||
		input.Architecture == "" ||
		input.DownloadURL == "" ||
		input.SHA256 == "" {

		writeError(
			w,
			http.StatusBadRequest,
			"incomplete core release",
		)
		return
	}

	if !strings.HasPrefix(
		input.DownloadURL,
		"https://",
	) {
		writeError(
			w,
			http.StatusBadRequest,
			"download_url must use https",
		)
		return
	}

	if !validSHA256(input.SHA256) {
		writeError(
			w,
			http.StatusBadRequest,
			"invalid sha256",
		)
		return
	}

	switch input.Channel {
	case "testing", "canary", "stable":
	default:
		writeError(
			w,
			http.StatusBadRequest,
			"invalid channel",
		)
		return
	}

	release, err :=
		a.store.CreateCoreRelease(
			r.Context(),
			model.CoreReleaseRecord{
				Type:               input.Type,
				Version:            input.Version,
				OS:                 input.OS,
				Architecture:       input.Architecture,
				DownloadURL:        input.DownloadURL,
				SHA256:             input.SHA256,
				Channel:            input.Channel,
				UpstreamPrerelease: input.UpstreamPrerelease,
			},
		)

	if err != nil {
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		release,
	)
}

func (a *application) approveCoreRelease(
	w http.ResponseWriter,
	r *http.Request,
) {
	id := r.PathValue("id")

	if err := a.store.ApproveCoreRelease(
		r.Context(),
		id,
	); err != nil {

		if errors.Is(
			err,
			store.ErrNotFound,
		) {
			writeError(
				w,
				http.StatusNotFound,
				"core release not found or revoked",
			)
			return
		}

		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	w.WriteHeader(
		http.StatusNoContent,
	)
}

func (a *application) promoteCoreRelease(
	w http.ResponseWriter,
	r *http.Request,
) {
	id := r.PathValue("id")

	var input struct {
		Channel string `json:"channel"`
	}

	if err := readJSON(
		r,
		&input,
	); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.Channel =
		strings.ToLower(
			strings.TrimSpace(
				input.Channel,
			),
		)

	switch input.Channel {
	case "testing", "canary", "stable":
	default:
		writeError(
			w,
			http.StatusBadRequest,
			"invalid channel",
		)
		return
	}

	err :=
		a.store.PromoteCoreRelease(
			r.Context(),
			id,
			input.Channel,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"core release not found",
		)
		return
	}

	if errors.Is(
		err,
		store.ErrCoreReleaseNotApproved,
	) ||
		errors.Is(
			err,
			store.ErrCoreReleaseRevoked,
		) ||
		errors.Is(
			err,
			store.ErrCoreReleaseAlreadyChannel,
		) ||
		errors.Is(
			err,
			store.ErrCoreReleaseDowngrade,
		) ||
		errors.Is(
			err,
			store.ErrCoreReleasePrereleaseStable,
		) {

		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	w.WriteHeader(
		http.StatusNoContent,
	)
}

func (a *application) revokeCoreRelease(
	w http.ResponseWriter,
	r *http.Request,
) {
	id := r.PathValue("id")

	err :=
		a.store.RevokeCoreRelease(
			r.Context(),
			id,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"core release not found",
		)
		return
	}

	if errors.Is(
		err,
		store.ErrCoreReleaseAlreadyRevoked,
	) {
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	w.WriteHeader(
		http.StatusNoContent,
	)
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}

	for _, char := range value {
		isDigit :=
			char >= '0' && char <= '9'

		isLowerHex :=
			char >= 'a' && char <= 'f'

		isUpperHex :=
			char >= 'A' && char <= 'F'

		if !isDigit &&
			!isLowerHex &&
			!isUpperHex {
			return false
		}
	}

	return true
}

func (a *application) rebuildNodeDesiredState(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID := strings.TrimSpace(
		r.PathValue("id"),
	)
	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	state, err :=
		a.store.RebuildNodeDesiredState(
			r.Context(),
			nodeID,
		)

	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusAccepted,
		state,
	)
}

func (a *application) setDesiredState(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID := r.PathValue("id")

	var state model.DesiredState

	if err := readJSON(
		r,
		&state,
	); err != nil {
		writeError(w, 400, err.Error())
		return
	}

	if state.Generation < 1 {
		writeError(
			w,
			http.StatusBadRequest,
			"generation must be >= 1",
		)
		return
	}

	state.Core.Type =
		strings.TrimSpace(state.Core.Type)

	state.Core.Version =
		strings.TrimSpace(state.Core.Version)

	if state.Core.Type == "" ||
		state.Core.Version == "" {

		writeError(
			w,
			http.StatusBadRequest,
			"core type and version are required",
		)
		return
	}

	resolved, err :=
		a.store.ResolveCoreRelease(
			r.Context(),
			nodeID,
			state.Core.Type,
			state.Core.Version,
		)

	if errors.Is(err, store.ErrNotFound) {
		writeError(
			w,
			http.StatusNotFound,
			"approved core release not found for node platform",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	// URL, SHA-256 and channel are controlled exclusively
	// by Core Registry. Client-supplied values are ignored.
	state.Core = resolved.Release

	err = a.store.SaveDesiredState(
		r.Context(),
		nodeID,
		state,
		resolved.ID,
	)

	if errors.Is(err, store.ErrNotFound) {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{
			"node_id":         nodeID,
			"generation":      state.Generation,
			"status":          "accepted",
			"core_type":       state.Core.Type,
			"core_version":    state.Core.Version,
			"core_channel":    state.Core.Channel,
			"core_release_id": resolved.ID,
		},
	)
}

func (a *application) registerAgent(
	w http.ResponseWriter,
	r *http.Request,
) {
	bootstrapToken := bearerToken(r)

	if bootstrapToken == "" {
		writeError(
			w,
			http.StatusUnauthorized,
			"bootstrap token required",
		)
		return
	}

	var input struct {
		AgentVersion string `json:"agent_version"`
		RuntimeCore  string `json:"runtime_core"`
		OSName       string `json:"os_name"`
		OSVersion    string `json:"os_version"`
		Architecture string `json:"architecture"`
	}

	if err := readJSON(
		r,
		&input,
	); err != nil {

		writeError(w, 400, err.Error())
		return
	}

	input.RuntimeCore = strings.TrimSpace(input.RuntimeCore)
	if input.RuntimeCore == "" {
		input.RuntimeCore = "xray"
	}
	if !model.ValidRuntimeCore(input.RuntimeCore) || (input.RuntimeCore == "amneziawg" && !model.AmneziaWGAgentCompatible(input.AgentVersion)) || (input.RuntimeCore == "pptp" && !model.PPTPAgentCompatible(input.AgentVersion)) || (input.RuntimeCore == "wireguard" && !model.NativeWireGuardAgentCompatible(input.AgentVersion)) || (input.RuntimeCore == "openvpn" && !model.OpenVPNAgentCompatible(input.AgentVersion)) || (input.RuntimeCore == "hysteria2" && !store.HysteriaAgentOperationallyCompatible(input.AgentVersion)) {
		writeError(w, 400, "unsupported runtime or incompatible agent version")
		return
	}
	agentToken, err :=
		security.NewToken(48)

	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	node, err :=
		a.store.BootstrapAgentForRuntime(
			r.Context(),

			security.HashToken(
				bootstrapToken,
			),

			security.HashToken(
				agentToken,
			),

			input.AgentVersion,
			input.OSName,
			input.OSVersion,
			input.Architecture,
			input.RuntimeCore,
		)

	if errors.Is(err, store.ErrNotFound) {
		writeError(
			w,
			http.StatusUnauthorized,
			"invalid or already used bootstrap token",
		)
		return
	}

	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"node_id":      node.ID,
			"tenant_id":    node.TenantID,
			"agent_token":  agentToken,
			"runtime_core": node.RuntimeCore,
		},
	)
}

func (a *application) agentDesiredState(
	w http.ResponseWriter,
	r *http.Request,
) {
	node := currentNode(r.Context())

	state, exists, err :=
		a.store.LegacyAgentDesiredState(
			r.Context(),
			node.ID,
		)

	if errors.Is(err, store.ErrXrayProfileLegacy) || errors.Is(err, store.ErrXrayProfileIdentity) || errors.Is(err, store.ErrXrayProfileHeld) || errors.Is(err, store.ErrNodeRuntime) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	if !exists {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		state,
	)
}

func (a *application) agentAssignment(
	w http.ResponseWriter,
	r *http.Request,
) {
	node :=
		currentNode(
			r.Context(),
		)

	assignment, exists, err :=
		a.store.AgentAssignment(
			r.Context(),
			node.ID,
		)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)

		return
	}

	if !exists {
		w.WriteHeader(
			http.StatusNoContent,
		)

		return
	}

	writeJSON(
		w,
		http.StatusOK,
		assignment,
	)
}

func (a *application) agentHealth(
	w http.ResponseWriter,
	r *http.Request,
) {
	node := currentNode(r.Context())

	var report model.HealthReport

	if err := readJSON(
		r,
		&report,
	); err != nil {

		writeError(w, 400, err.Error())
		return
	}

	if report.CheckedAt.IsZero() {
		report.CheckedAt =
			time.Now().UTC()
	}

	if !validNodeMetrics(report.Metrics) {
		writeError(w, http.StatusBadRequest, "invalid node metrics")
		return
	}
	if !validClientTraffic(report.ClientTraffic) || !validTrafficSnapshot(report.TrafficSnapshot) || (report.TrafficSnapshot != nil && len(report.ClientTraffic) > 0) {
		writeError(w, http.StatusBadRequest, "invalid client traffic")
		return
	}

	if err :=
		a.store.SaveHealth(
			r.Context(),
			node.ID,
			report,
		); err != nil {

		if errors.Is(err, store.ErrNodeRuntime) {
			writeError(w, http.StatusConflict, "health runtime or agent release differs from node selection")
			return
		}
		writeError(w, 500, err.Error())
		return
	}

	w.WriteHeader(
		http.StatusNoContent,
	)
}

func (a *application) agentDeploymentStatus(
	w http.ResponseWriter,
	r *http.Request,
) {
	node, ok :=
		r.Context().
			Value(nodeContextKey).(model.Node)

	if !ok {
		writeError(
			w,
			http.StatusUnauthorized,
			"agent node context missing",
		)
		return
	}

	var report model.DeploymentReport

	if err := readJSON(
		r,
		&report,
	); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	if report.Generation < 1 {
		writeError(
			w,
			http.StatusBadRequest,
			"generation must be >= 1",
		)
		return
	}

	switch report.Status {
	case "applying",
		"healthy",
		"failed",
		"rolled_back":
	default:
		writeError(
			w,
			http.StatusBadRequest,
			"invalid deployment status",
		)
		return
	}

	if report.ReportedAt.IsZero() {
		report.ReportedAt =
			time.Now().UTC()
	}

	err :=
		a.store.SaveDeploymentReport(
			r.Context(),
			node.ID,
			report,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"deployment not found",
		)
		return
	}

	if errors.Is(
		err,
		store.ErrExecutionLeaseProofIncomplete,
	) {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	if errors.Is(
		err,
		store.ErrExecutionLeaseProofRequired,
	) ||
		errors.Is(
			err,
			store.ErrExecutionLeaseConflict,
		) ||
		errors.Is(
			err,
			store.ErrExecutionLeaseExpired,
		) {

		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	if errors.Is(
		err,
		store.ErrExecutionIdentityIncomplete,
	) {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	if errors.Is(
		err,
		store.ErrExecutionIdentityMismatch,
	) {
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	if errors.Is(
		err,
		store.ErrInvalidDeploymentTransition,
	) {
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	w.WriteHeader(
		http.StatusNoContent,
	)
}

type contextKey string

const nodeContextKey contextKey = "node"

func (a *application) requireAgent(
	next http.HandlerFunc,
) http.HandlerFunc {

	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		token := bearerToken(r)

		if token == "" {
			writeError(
				w,
				http.StatusUnauthorized,
				"agent token required",
			)
			return
		}

		node, err :=
			a.store.NodeByAgentToken(
				r.Context(),

				security.HashToken(
					token,
				),
			)

		if errors.Is(
			err,
			store.ErrNotFound,
		) {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid agent token",
			)
			return
		}

		if err != nil {
			writeError(
				w,
				500,
				err.Error(),
			)
			return
		}

		ctx :=
			context.WithValue(
				r.Context(),
				nodeContextKey,
				node,
			)

		next(
			w,
			r.WithContext(ctx),
		)
	}
}

func currentNode(
	ctx context.Context,
) model.Node {

	return ctx.Value(
		nodeContextKey,
	).(model.Node)
}

func (a *application) requireAdmin(
	next http.HandlerFunc,
) http.HandlerFunc {

	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		token := bearerToken(r)

		if token != "" && security.EqualSecret(token, a.adminToken) {
			next(w, r)
			return
		}
		if !adminSessionPattern.MatchString(token) {
			writeError(w, 401, "invalid administrative credential")
			return
		}
		session, err := a.store.AuthenticateAdminSession(r.Context(), security.HashToken(token))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 401, "session expired or revoked")
			return
		}
		if err != nil {
			writeError(w, 503, "session service unavailable")
			return
		}
		r = r.WithContext(store.WithAdminPrincipal(r.Context(), session))
		authorized := func(w http.ResponseWriter, r *http.Request) {
			if session.Account.Role == "monitor" && !monitorRouteAllowed(r.Pattern) {
				writeError(w, 403, "read-only monitoring access")
				return
			}
			next(w, r)
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			serveAuditedAdminMutation(w, r, authorized, a.store.BeginAdminMutation, a.store.CompleteAdminMutation)
			return
		}
		authorized(w, r)
	}
}

func bearerToken(
	r *http.Request,
) string {

	const prefix = "Bearer "

	value :=
		r.Header.Get(
			"Authorization",
		)

	if !strings.HasPrefix(
		value,
		prefix,
	) {
		return ""
	}

	return strings.TrimSpace(
		strings.TrimPrefix(
			value,
			prefix,
		),
	)
}

func readJSON(
	r *http.Request,
	dst any,
) error {

	decoder :=
		json.NewDecoder(
			r.Body,
		)

	decoder.DisallowUnknownFields()

	return decoder.Decode(dst)
}

func writeJSON(
	w http.ResponseWriter,
	status int,
	value any,
) {
	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	w.WriteHeader(status)

	if status !=
		http.StatusNoContent {

		_ = json.NewEncoder(w).
			Encode(value)
	}
}

func writeError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	writeJSON(
		w,
		status,
		map[string]string{
			"error": message,
		},
	)
}

func loggingMiddleware(
	next http.Handler,
) http.Handler {

	return http.HandlerFunc(
		func(
			w http.ResponseWriter,
			r *http.Request,
		) {
			start := time.Now()

			next.ServeHTTP(w, r)

			log.Printf(
				"%s %s %s",
				r.Method,
				safeRequestLogPath(r),
				time.Since(start),
			)
		},
	)
}

func mustEnv(
	name string,
) string {

	value :=
		strings.TrimSpace(
			os.Getenv(name),
		)

	if value == "" {
		log.Fatalf(
			"%s is required",
			name,
		)
	}

	return value
}

func env(
	name string,
	fallback string,
) string {

	value :=
		strings.TrimSpace(
			os.Getenv(name),
		)

	if value == "" {
		return fallback
	}

	return value
}

func (a *application) coreUpdateStatus(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	coreType :=
		strings.TrimSpace(
			r.URL.Query().Get("core"),
		)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	if coreType == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"core query parameter is required",
		)
		return
	}

	status, err :=
		a.store.GetCoreUpdateStatus(
			r.Context(),
			nodeID,
			coreType,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		status,
	)
}

func (a *application) setCoreUpdatePolicy(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	var input struct {
		CoreType      string `json:"core_type"`
		Policy        string `json:"policy"`
		PinnedVersion string `json:"pinned_version"`
	}

	if err := readJSON(
		r,
		&input,
	); err != nil {

		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.CoreType =
		strings.TrimSpace(
			input.CoreType,
		)

	input.Policy =
		strings.TrimSpace(
			input.Policy,
		)

	input.PinnedVersion =
		strings.TrimSpace(
			input.PinnedVersion,
		)

	if input.CoreType == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"core_type is required",
		)
		return
	}

	policy, changed, err :=
		a.store.SetCoreUpdatePolicy(
			r.Context(),
			nodeID,
			input.CoreType,
			input.Policy,
			input.PinnedVersion,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return

	case errors.Is(
		err,
		store.ErrInvalidCoreUpdatePolicy,
	),
		errors.Is(
			err,
			store.ErrPinnedVersionRequired,
		),
		errors.Is(
			err,
			store.ErrPinnedVersionNotAllowed,
		):

		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return

	case errors.Is(
		err,
		store.ErrPinnedCoreReleaseUnavailable,
	):
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"changed": changed,

			"policy": policy,
		},
	)
}

func (a *application) coreUpdateEvaluate(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	coreType :=
		strings.TrimSpace(
			r.URL.Query().Get("core"),
		)

	version :=
		strings.TrimSpace(
			r.URL.Query().Get("version"),
		)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	if coreType == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"core query parameter is required",
		)
		return
	}

	if version == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"version query parameter is required",
		)
		return
	}

	evaluation, err :=
		a.store.EvaluateCoreUpdate(
			r.Context(),
			nodeID,
			coreType,
			version,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		evaluation,
	)
}

func (a *application) createRolloutPlan(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	var input struct {
		CoreType string `json:"core_type"`
	}

	if err := readJSON(
		r,
		&input,
	); err != nil {

		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.CoreType =
		strings.TrimSpace(
			input.CoreType,
		)

	if input.CoreType == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"core_type is required",
		)
		return
	}

	plan, err :=
		a.store.CreateCoreRolloutPlan(
			r.Context(),
			nodeID,
			input.CoreType,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		plan,
	)
}

func (a *application) getRolloutPlan(
	w http.ResponseWriter,
	r *http.Request,
) {
	planID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	plan, err :=
		a.store.GetRolloutPlan(
			r.Context(),
			planID,
		)

	if errors.Is(
		err,
		store.ErrNotFound,
	) {
		writeError(
			w,
			http.StatusNotFound,
			"rollout plan not found",
		)
		return
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		plan,
	)
}

func (a *application) approveRolloutPlan(
	w http.ResponseWriter,
	r *http.Request,
) {
	planID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	plan, err :=
		a.store.ApproveRolloutPlan(
			r.Context(),
			planID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"rollout plan not found",
		)
		return

	case errors.Is(
		err,
		store.ErrRolloutPlanBlocked,
	),
		errors.Is(
			err,
			store.ErrRolloutPlanAlreadyApproved,
		),
		errors.Is(
			err,
			store.ErrRolloutPlanNotApprovable,
		),
		errors.Is(
			err,
			store.ErrRolloutPlanStale,
		):

		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		plan,
	)
}

func (a *application) cancelRolloutPlan(
	w http.ResponseWriter,
	r *http.Request,
) {
	planID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	plan, changed, err :=
		a.store.CancelRolloutPlan(
			r.Context(),
			planID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"rollout plan not found",
		)
		return

	case errors.Is(
		err,
		store.ErrRolloutPlanTerminal,
	):
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"changed": changed,

			"plan": plan,
		},
	)
}

func (a *application) executeRolloutPlan(
	w http.ResponseWriter,
	r *http.Request,
) {
	planID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if planID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"rollout plan id is required",
		)
		return
	}

	plan, changed, err :=
		a.store.ExecuteRolloutPlan(
			r.Context(),
			planID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"rollout plan not found",
		)
		return

	case errors.Is(
		err,
		store.ErrRolloutPlanStale,
	):
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return

	case errors.Is(
		err,
		store.ErrRolloutPlanNotExecutable,
	):
		writeError(
			w,
			http.StatusConflict,
			err.Error(),
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"changed": changed,

			"plan": plan,
		},
	)
}
