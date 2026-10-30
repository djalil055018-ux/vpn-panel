//go:build integration

package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

func TestHysteriaServicesAndPlansIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated clone required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("clone connection failed")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing live database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// The reviewed artifact has a global unique identity. The HTTP package uses
	// the same clone, so hold a session lock through all deferred fixture cleanup.
	fixtureLock, err := p.Pool.Acquire(ctx)
	check(err)
	defer fixtureLock.Release()
	_, err = fixtureLock.Exec(ctx, `SELECT pg_advisory_lock(1448103505,7286122)`)
	check(err)
	defer func() {
		_, err := fixtureLock.Exec(context.Background(), `SELECT pg_advisory_unlock(1448103505,7286122)`)
		if err != nil {
			t.Error("release fixture lock cleanup failed")
		}
	}()
	// Never adopt or change a pre-existing registry artifact, even in the clone.
	var exists bool
	check(p.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_releases WHERE core_type='hysteria2' AND version=$1 AND os='linux' AND architecture='amd64')`, model.HysteriaPinnedVersion).Scan(&exists))
	if exists {
		t.Fatal("isolated release fixture already exists")
	}
	release, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "hysteria2", Version: model.HysteriaPinnedVersion, OS: "linux", Architecture: "amd64", DownloadURL: model.HysteriaPinnedDownloadURL, SHA256: model.HysteriaPinnedSHA256, Channel: "testing"})
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM core_releases WHERE id=$1::uuid`, release.ID)
	tenant, err := p.CreateTenant(ctx, "CODEX-HYSTERIA-SERVICES")
	check(err)
	defer func() {
		// Remove TLS bindings via services before cascading node certificates.
		if _, e := p.Pool.Exec(context.Background(), `DELETE FROM vpn_services WHERE tenant_id=$1::uuid`, tenant.ID); e != nil {
			t.Error("fixture service cleanup failed", e)
		}
		if _, e := p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID); e != nil {
			t.Error("fixture tenant cleanup failed", e)
		}
	}()
	bootstrap := security.HashToken("fixture-hys-services-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "CODEX-HYSTERIA-SERVICES", bootstrap, "hysteria2")
	check(err)
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("fixture-hys-services-agent"), "0.2.25", "ubuntu", "24.04", "amd64", "hysteria2")
	check(err)
	state := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: release.Type, Version: release.Version, DownloadURL: release.DownloadURL, SHA256: release.SHA256, Channel: release.Channel}}
	if p.SaveDesiredState(ctx, node.ID, state, release.ID) == nil {
		t.Fatal("unapproved release accepted")
	}
	check(p.ApproveCoreRelease(ctx, release.ID))
	_, _, err = p.SetCoreUpdatePolicy(ctx, node.ID, "hysteria2", "testing", "")
	check(err)
	update, err := p.GetCoreUpdateStatus(ctx, node.ID, "hysteria2")
	check(err)
	if !update.CandidateAvailable || update.CandidateReleaseID != release.ID {
		t.Fatal("reviewed Hysteria update missing")
	}
	unreviewed, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "hysteria2", Version: "2.12.3", OS: "linux", Architecture: "amd64", DownloadURL: model.HysteriaPinnedDownloadURL, SHA256: model.HysteriaPinnedSHA256, Channel: "testing"})
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM core_releases WHERE id=$1::uuid`, unreviewed.ID)
	check(p.ApproveCoreRelease(ctx, unreviewed.ID))
	update, err = p.GetCoreUpdateStatus(ctx, node.ID, "hysteria2")
	check(err)
	if update.CandidateReleaseID != release.ID {
		t.Fatal("higher unreviewed version displaced reviewed artifact")
	}
	evaluation, err := p.EvaluateCoreUpdate(ctx, node.ID, "hysteria2", "2.12.3")
	check(err)
	if evaluation.Eligible || !strings.Contains(strings.Join(evaluation.Blockers, ","), "unsupported_runtime_artifact") {
		t.Fatal("unreviewed runtime evaluation eligible")
	}
	if _, _, e := p.SetCoreUpdatePolicy(ctx, node.ID, "hysteria2", "pinned", "2.12.3"); e == nil {
		t.Fatal("policy pinned unreviewed artifact")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.23' WHERE id=$1::uuid`, node.ID)
	check(err)
	if _, _, e := p.InitializeHysteriaRuntime(ctx, node.ID); e == nil {
		t.Fatal("old agent initialized")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.25' WHERE id=$1::uuid`, node.ID)
	check(err)
	type initialization struct {
		state   model.DesiredState
		changed bool
		err     error
	}
	results := make(chan initialization, 2)
	for i := 0; i < 2; i++ {
		go func() {
			s, changed, e := p.InitializeHysteriaRuntime(ctx, node.ID)
			results <- initialization{s, changed, e}
		}()
	}
	changes := 0
	for i := 0; i < 2; i++ {
		result := <-results
		check(result.err)
		if result.changed {
			changes++
		}
		if result.state.Generation != 1 || len(result.state.Services) != 0 {
			t.Fatal("initial state is not idle generation one")
		}
	}
	if changes != 1 {
		t.Fatal("concurrent initialization created multiple deployments")
	}
	// Simulate an older running release to exercise an existing upgrade plan;
	// this is planner validation, not a native cross-release upgrade proof.
	check(p.SaveHealth(ctx, node.ID, model.HealthReport{Core: "hysteria2", CoreVersion: "2.12.1", AgentVersion: "0.2.25", AppliedGeneration: 1, Healthy: true, CheckedAt: time.Now()}))
	rollout, err := p.CreateCoreRolloutPlan(ctx, node.ID, "hysteria2")
	check(err)
	if rollout.Status != "planned" {
		t.Fatal("fixture upgrade plan was not eligible")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.23' WHERE id=$1::uuid`, node.ID)
	check(err)
	if _, e := p.ApproveRolloutPlan(ctx, rollout.ID); !errors.Is(e, ErrRolloutPlanStale) {
		t.Fatal("existing Hysteria plan approved for old agent")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.25' WHERE id=$1::uuid`, node.ID)
	check(err)
	_, err = p.ApproveRolloutPlan(ctx, rollout.ID)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE core_releases SET sha256=$2 WHERE id=$1::uuid`, release.ID, strings.Repeat("0", 64))
	check(err)
	stale, changed, e := p.ExecuteRolloutPlan(ctx, rollout.ID)
	if !errors.Is(e, ErrRolloutPlanStale) || changed || stale.Status != "stale" {
		t.Fatal("approved plan executed after reviewed artifact drift")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE core_releases SET sha256=$2 WHERE id=$1::uuid`, release.ID, model.HysteriaPinnedSHA256)
	check(err)
	address, port := "hys-service.example.test", 18443
	service, err := p.CreateVPNService(ctx, node.ID, "Hysteria fixture", "hysteria2", "0.0.0.0", port, "udp", "tls", &address, &port)
	check(err)
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true); err == nil {
		t.Fatal("service without certificate enabled")
	}
	makeCert := func(environment, domain string) string {
		t.Helper()
		cert, e := p.CreateNodeCertificate(ctx, node.ID, domain, "letsencrypt", "http-01", environment, nil, true)
		check(e)
		_, e = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_before=now()-interval '1 day',not_after=now()+interval '60 days' WHERE id=$1::uuid`, cert.ID)
		check(e)
		return cert.ID
	}
	staging := makeCert("staging", "hys-staging.example.test")
	if _, _, err = p.ConfigureVPNServiceTLS(ctx, service.ID, staging); err == nil {
		t.Fatal("staging certificate accepted")
	}
	cert := makeCert("production", address)
	_, _, err = p.ConfigureVPNServiceTLS(ctx, service.ID, cert)
	check(err)
	state, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(err)
	if len(state.Services) != 1 || state.Services[0].TLS == nil || state.Services[0].TLS.CertificateID != cert || state.Services[0].TLS.KeyFile != "" {
		t.Fatal("Hysteria desired TLS metadata invalid")
	}
	plan, err := p.CreateVPNAccessPlan(ctx, tenant.ID, "Hysteria fixture", "hys-fixture", true)
	check(err)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service.ID, true)
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "Hysteria fixture client", nil)
	check(err)
	readState := func() model.DesiredState {
		t.Helper()
		var raw []byte
		var s model.DesiredState
		check(p.Pool.QueryRow(ctx, `SELECT d.document FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, node.ID).Scan(&raw))
		check(json.Unmarshal(raw, &s))
		return s
	}
	assertAccess := func(count int) {
		t.Helper()
		s := readState()
		if len(s.Services) != 1 || len(s.Services[0].Clients) != count {
			t.Fatal("effective desired access differs")
		}
		connections, e := p.ListVPNClientConnections(ctx, client.ID)
		check(e)
		if len(connections) != count {
			t.Fatal("subscription differs from effective access")
		}
		if count == 1 && (connections[0].Protocol != "hysteria2" || connections[0].Transport != "udp" || connections[0].ServerName != address || s.Services[0].Clients[0].StatsKey != client.ID) {
			t.Fatal("Hysteria connection or accounting identity differs")
		}
	}
	assertAccess(0)
	mutation, err := p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	if len(mutation.Rebuilds) != 1 || mutation.Rebuilds[0].NodeID != node.ID {
		t.Fatal("plan assignment did not rebuild selected node")
	}
	assertAccess(1)
	before := readState().Generation
	mutation, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	if mutation.Changed || len(mutation.Rebuilds) != 0 || readState().Generation != before {
		t.Fatal("idempotent assignment changed generation")
	}
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, false)
	check(err)
	assertAccess(0)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, false)
	check(err)
	assertAccess(1)

	// Direct revoke must remove membership and rebuild the node atomically.
	beforeDetach := readState().Generation
	detached, err := p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	if detached.Generation != beforeDetach+1 || readState().Generation != beforeDetach+1 {
		t.Fatal("direct detach did not rebuild desired generation")
	}
	assertAccess(0)

	// Restore direct access for the remaining Hysteria lifecycle checks.
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertAccess(1)

	// A failed rebuild must roll back the plan membership and generation together.
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.23' WHERE id=$1::uuid`, node.ID)
	check(err)
	update, err = p.GetCoreUpdateStatus(ctx, node.ID, "hysteria2")
	check(err)
	if update.CandidateAvailable {
		t.Fatal("old agent offered Hysteria update")
	}
	evaluation, err = p.EvaluateCoreUpdate(ctx, node.ID, "hysteria2", model.HysteriaPinnedVersion)
	check(err)
	if evaluation.Eligible {
		t.Fatal("old agent update evaluation eligible")
	}
	before = readState().Generation
	if _, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true); err == nil {
		t.Fatal("old agent accepted Hysteria plan")
	}
	var memberships int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM vpn_client_access_plans WHERE plan_id=$1::uuid`, plan.ID).Scan(&memberships))
	if memberships != 0 || readState().Generation != before {
		t.Fatal("failed plan mutation was not atomic")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.25' WHERE id=$1::uuid`, node.ID)
	check(err)
	// Direct desired-state submissions cannot bypass the same service/runtime gate.
	for _, mutate := range []func(*model.DesiredState){
		func(s *model.DesiredState) { s.Core.SHA256 = strings.Repeat("0", 64) },
		func(s *model.DesiredState) { s.Services = append(s.Services, s.Services[0]) },
		func(s *model.DesiredState) { s.Services[0].TLS.ServerName = "wrong.example.test" },
		func(s *model.DesiredState) {
			s.Services[0].Clients = append(s.Services[0].Clients, s.Services[0].Clients[0])
		},
	} {
		bad := readState()
		bad.Generation++
		mutate(&bad)
		if p.SaveDesiredState(ctx, node.ID, bad, release.ID) == nil {
			t.Fatal("invalid direct Hysteria desired accepted")
		}
	}
	if readState().Generation != before {
		t.Fatal("rejected desired state advanced generation")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE node_certificates SET not_after=now()-interval '1 hour' WHERE id=$1::uuid`, cert)
	check(err)
	if _, err = p.RebuildNodeDesiredState(ctx, node.ID); err == nil {
		t.Fatal("expired certificate accepted")
	}
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if len(connections) != 0 {
		t.Fatal("expired certificate still advertised")
	}
	state, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, false)
	check(err)
	if len(state.Services) != 0 {
		t.Fatal("disable did not produce idle state")
	}
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true); err == nil {
		t.Fatal("expired service re-enabled")
	}
	var enabled bool
	check(p.Pool.QueryRow(ctx, `SELECT enabled FROM vpn_services WHERE id=$1::uuid`, service.ID).Scan(&enabled))
	if enabled {
		t.Fatal("failed enable committed")
	}
}
