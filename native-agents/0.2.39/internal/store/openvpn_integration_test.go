//go:build integration

package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/pki"
	"vpn-platform/internal/security"
)

func TestOpenVPNAccessIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	defer p.Close()
	var db string
	if p.Pool.QueryRow(ctx, "SELECT current_database()").Scan(&db) != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "OpenVPN integration")
	check(err)
	var releaseID string
	defer func() {
		_, e := p.Pool.Exec(context.Background(), `DELETE FROM vpn_services WHERE tenant_id=$1::uuid`, tenant.ID)
		check(e)
		_, e = p.Pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1::uuid`, tenant.ID)
		check(e)
		if releaseID != "" {
			_, e = p.Pool.Exec(context.Background(), `DELETE FROM core_releases WHERE id=$1::uuid`, releaseID)
			check(e)
		}
	}()
	release, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "openvpn", Version: model.OpenVPNPinnedVersion, OS: "linux", Architecture: "amd64", DownloadURL: model.OpenVPNPinnedDownloadURL, SHA256: model.OpenVPNPinnedSHA256, Channel: "testing"})
	check(err)
	releaseID = release.ID
	check(p.ApproveCoreRelease(ctx, release.ID))
	bootstrap := security.HashToken("openvpn-fixture-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "OpenVPN test", bootstrap, "openvpn")
	check(err)
	if _, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("openvpn-fixture-agent"), "0.2.26", "ubuntu", "24.04", "amd64", "openvpn"); err == nil {
		t.Fatal("old agent accepted OpenVPN runtime")
	}
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("openvpn-fixture-agent"), "0.2.27", "ubuntu", "24.04", "amd64", "openvpn")
	check(err)
	initial := model.DesiredState{Generation: 1, Core: model.CoreRelease{Type: release.Type, Version: release.Version, DownloadURL: release.DownloadURL, SHA256: release.SHA256, Channel: release.Channel}}
	check(p.SaveDesiredState(ctx, node.ID, initial, release.ID))
	address, port := "openvpn.example.test", 1194
	service, err := p.CreateVPNService(ctx, node.ID, "OpenVPN test", "openvpn", "127.0.0.1", port, "udp", "tls", &address, &port)
	check(err)
	_, err = p.SetVPNServiceEnabledAndRebuild(ctx, service.ID, true)
	check(err)
	client, err := p.CreateVPNClient(ctx, tenant.ID, "OpenVPN client", nil)
	check(err)
	var originalConfig string
	assertAccess := func(want int) {
		t.Helper()
		connections, e := p.ListVPNClientConnections(ctx, client.ID)
		check(e)
		if len(connections) != want {
			t.Fatalf("connections=%d want%d", len(connections), want)
		}
		var raw []byte
		check(p.Pool.QueryRow(ctx, `SELECT d.document FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, node.ID).Scan(&raw))
		var state model.DesiredState
		check(json.Unmarshal(raw, &state))
		if len(state.Services) != 1 || len(state.Services[0].Clients) != want || state.Services[0].OpenVPN == nil {
			t.Fatal("desired access differs")
		}
		var caPrivate string
		check(p.Pool.QueryRow(ctx, `SELECT ca_private_key FROM vpn_service_openvpn WHERE service_id=$1::uuid`, service.ID).Scan(&caPrivate))
		decoded, _ := json.Marshal(state)
		encodedCA, _ := json.Marshal(caPrivate)
		if strings.Contains(string(decoded), string(encodedCA)) {
			t.Fatal("CA signing key was sent to agent")
		}
		if want == 1 {
			if !strings.Contains(connections[0].Config, "remote-cert-tls server") || !strings.HasSuffix(connections[0].ConfigFilename, ".ovpn") {
				t.Fatal("OpenVPN profile missing")
			}
			if originalConfig == "" {
				originalConfig = connections[0].Config
			}
			if state.Services[0].Clients[0].StatsKey != client.ID {
				t.Fatal("traffic identity missing")
			}
		}
		var serial string
		e = p.Pool.QueryRow(ctx, `SELECT serial FROM vpn_client_openvpn_certificates WHERE service_id=$1::uuid AND client_id=$2::uuid ORDER BY created_at DESC LIMIT 1`, service.ID, client.ID).Scan(&serial)
		if e == nil {
			block, _ := pem.Decode([]byte(state.Services[0].OpenVPN.CRL))
			crl, e := x509.ParseRevocationList(block.Bytes)
			check(e)
			revoked := false
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.String() == serial {
					revoked = true
				}
			}
			if revoked != (want == 0) {
				t.Fatal("CRL differs from effective access")
			}
		}
	}
	assertAccess(0)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertAccess(1)
	// OpenVPN desired identities are client IDs, not VLESS credentials.
	countStable, e := p.ReconcileInactiveVPNClients(ctx)
	check(e)
	if countStable != 0 {
		t.Fatal("active OpenVPN access rebuilt unnecessarily")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=now()-interval '1 second' WHERE id=$1::uuid`, client.ID)
	check(err)
	countExpired, e := p.ReconcileInactiveVPNClients(ctx)
	check(e)
	if countExpired != 1 {
		t.Fatal("expired OpenVPN access was not reconciled")
	}
	assertAccess(0)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET expires_at=NULL WHERE id=$1::uuid`, client.ID)
	check(err)
	countRestored, e := p.ReconcileInactiveVPNClients(ctx)
	check(e)
	if countRestored != 1 {
		t.Fatal("renewed OpenVPN access was not restored")
	}
	assertAccess(1)
	plan, err := p.CreateVPNAccessPlan(ctx, tenant.ID, "OpenVPN plan", "openvpn-plan", true)
	check(err)
	_, err = p.SetVPNAccessPlanService(ctx, plan.ID, service.ID, true)
	check(err)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, true)
	check(err)
	assertNativeContinuousQuota(t, p, ctx, client.ID, assertAccess)
	_, err = p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertAccess(1)
	_, err = p.SetVPNClientAccessPlan(ctx, plan.ID, client.ID, false)
	check(err)
	assertAccess(0)
	_, err = p.AttachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertAccess(1)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.26' WHERE id=$1::uuid`, node.ID)
	check(err)
	if _, err = p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID); err == nil {
		t.Fatal("incompatible agent accepted rebuild")
	}
	assertAccess(1)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.27' WHERE id=$1::uuid`, node.ID)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_service_openvpn SET next_refresh_at=now()-interval '1 day' WHERE service_id=$1::uuid`, service.ID)
	check(err)
	count, err := p.ReconcileOpenVPNMaintenance(ctx)
	check(err)
	if count != 1 {
		t.Fatal("maintenance did not refresh node")
	}
	assertAccess(1)
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if connections[0].Config != originalConfig {
		t.Fatal("routine maintenance changed valid client keys")
	}
	if connections[0].ConfigExpiresAt == nil || connections[0].ConfigExpiresAt.Before(time.Now().AddDate(0, 11, 0)) {
		t.Fatal("profile expiry missing")
	}
	var ca pki.KeyPair
	check(p.Pool.QueryRow(ctx, `SELECT ca_certificate,ca_private_key FROM vpn_service_openvpn WHERE service_id=$1::uuid`, service.ID).Scan(&ca.Certificate, &ca.PrivateKey))
	oldPair, err := pki.Issue(ca, "client-"+client.ID, false, time.Now().AddDate(-1, 0, 20))
	check(err)
	oldCert, err := pki.ParseCertificate(oldPair.Certificate)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_client_openvpn_certificates SET serial=$3,certificate=$4,private_key=$5,expires_at=$6 WHERE service_id=$1::uuid AND client_id=$2::uuid`, service.ID, client.ID, oldPair.Serial, oldPair.Certificate, oldPair.PrivateKey, oldCert.NotAfter)
	check(err)
	_, err = p.RebuildNodeDesiredState(ctx, node.ID)
	check(err)
	assertAllCertificates := func(revoked bool) {
		t.Helper()
		var raw []byte
		check(p.Pool.QueryRow(ctx, `SELECT d.document FROM desired_states d JOIN nodes n ON n.id=d.node_id AND n.desired_generation=d.generation WHERE n.id=$1::uuid`, node.ID).Scan(&raw))
		var state model.DesiredState
		check(json.Unmarshal(raw, &state))
		block, _ := pem.Decode([]byte(state.Services[0].OpenVPN.CRL))
		crl, e := x509.ParseRevocationList(block.Bytes)
		check(e)
		revokedSerials := map[string]bool{}
		for _, entry := range crl.RevokedCertificateEntries {
			revokedSerials[entry.SerialNumber.String()] = true
		}
		rows, e := p.Pool.Query(ctx, `SELECT serial FROM vpn_client_openvpn_certificates WHERE service_id=$1::uuid AND client_id=$2::uuid`, service.ID, client.ID)
		check(e)
		defer rows.Close()
		count := 0
		for rows.Next() {
			var serial string
			check(rows.Scan(&serial))
			if revokedSerials[serial] != revoked {
				t.Fatal("renewed and previous certificate access differ")
			}
			count++
		}
		check(rows.Err())
		if count != 2 {
			t.Fatal("renewal did not issue exactly one new profile")
		}
	}
	assertAllCertificates(false)
	connections, err = p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if connections[0].ConfigExpiresAt == nil || !connections[0].ConfigExpiresAt.After(oldCert.NotAfter) {
		t.Fatal("download did not select renewed profile")
	}
	_, err = p.DetachVPNClientAndRebuild(ctx, service.ID, client.ID)
	check(err)
	assertAllCertificates(true)
}
