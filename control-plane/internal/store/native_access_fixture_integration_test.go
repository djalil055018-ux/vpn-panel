//go:build integration

package store

import (
	"context"
	"strings"
	"testing"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
)

// All identities and key material belong to the disposable test database.
// Lifecycle checks no longer depend on copying production nodes or credentials.
func nativeAccessFixture(t *testing.T, ctx context.Context, p *Postgres) (string, []string) {
	t.Helper()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, e := p.CreateTenant(ctx, "Synthetic native access "+t.Name())
	check(e)
	version := map[string]string{"TestAccessPlanAtomicIntegration": "99.0.11", "TestVPNClientLifecycleIntegration": "99.0.12", "TestVPNClientDeleteXrayIntegration": "99.0.13", "TestNodeDeleteClientHistoryIntegration": "99.0.14", "TestContinuousQuotaAccessAndAccountingIntegration": "99.0.15", "TestCascadeGroupLifecycleIntegration": "99.0.16"}[t.Name()]
	if t.Name() == "TestAutoProfileEligibilityIntegration" {
		version = "99.0.17"
	}
	if t.Name() == "TestVPNServiceDeleteRebuildIntegration" {
		version = "99.0.18"
	}
	if t.Name() == "TestNodeRenameIntegration" {
		version = "99.0.19"
	}
	if t.Name() == "TestNodeDeleteOnlineDecommissionIntegration" {
		version = "99.0.20"
	}
	if t.Name() == "TestVPNServiceConfigurationRebuildIntegration" {
		version = "99.0.21"
	}
	if t.Name() == "TestBillingIntegration" {
		version = "99.0.22"
	}
	if t.Name() == "TestCertificateManagementIntegration" {
		version = "99.0.23"
	}
	switch t.Name() {
	case "TestNodeRetirementGroupCleanupIntegration", "TestNodeGroupMembershipBackfillIntegration":
		version = "99.0.31"
	case "TestNodeDecommissionGroupCleanupIntegration":
		version = "99.0.32"
	case "TestAccessPlanRetiredCascadeIntegration":
		version = "99.0.30"
	case "TestTrafficRuntimeEpochAndReplayIntegration":
		version = "99.0.24"
	case "TestTrojanTLSIntegration":
		version = "99.0.25"
	case "TestVPNClientTrafficQuotaIntegration":
		version = "99.0.26"
	case "TestVPNServiceTLSIntegration":
		version = "99.0.27"
	case "TestXHTTPTLSIntegration":
		version = "99.0.28"
	case "TestCascadeDialPolicyIntegration":
		version = "99.0.29"
	}
	if version == "" {
		t.Fatal("unregistered native fixture")
	}
	release, e := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: version, OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/native-test.zip", SHA256: strings.Repeat("f", 64), Channel: "testing"})
	check(e)
	check(p.ApproveCoreRelease(ctx, release.ID))
	core := model.CoreRelease{Type: release.Type, Version: release.Version, DownloadURL: release.DownloadURL, SHA256: release.SHA256, Channel: release.Channel}
	services := []string{}
	for _, name := range []string{"first", "second"} {
		bootstrap := security.HashToken("native-test-bootstrap-" + tenant.ID + name)
		node, e := p.CreateNodeForRuntime(ctx, tenant.ID, name, bootstrap, "xray")
		check(e)
		_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("native-test-agent-"+tenant.ID+name), "0.2.31", "ubuntu", "24.04", "amd64", "xray")
		check(e)
		check(p.SaveDesiredState(ctx, node.ID, model.DesiredState{Generation: 1, Core: core}, release.ID))
		address, port := name+".example.test", 443
		service, e := p.CreateVPNService(ctx, node.ID, name, "vless", "0.0.0.0", port, "tcp", "reality", &address, &port)
		check(e)
		_, e = p.ConfigureVPNServiceReality(ctx, service.ID, "example.test:443", "example.test", "chrome", "0123456789abcdef")
		check(e)
		// This public X25519 value is synthetic; there is no production secret.
		_, e = p.Pool.Exec(ctx, `UPDATE vpn_service_reality SET public_key='BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc' WHERE service_id=$1::uuid`, service.ID)
		check(e)
		_, e = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
		check(e)
		services = append(services, service.ID)
	}
	return tenant.ID, services
}
