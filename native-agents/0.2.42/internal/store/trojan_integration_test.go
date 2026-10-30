//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTrojanTLSIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(60*time.Second))
	defer cancel()
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	defer p.Close()
	var db string
	if err = p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil || !strings.HasPrefix(db, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	const node = "50a85540-9f2c-4aa1-ba50-bc8c4267877d"
	const otherNode = "c0a50601-dacf-4e79-b496-389d17119032"
	var oldVersion string
	check(p.Pool.QueryRow(ctx, `SELECT agent_version FROM nodes WHERE id=$1::uuid`, node).Scan(&oldVersion))
	defer p.Pool.Exec(context.Background(), `UPDATE nodes SET agent_version=$2 WHERE id=$1::uuid`, node, oldVersion)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.16' WHERE id=$1::uuid`, node)
	check(err)
	certificateIDs := []string{}
	defer func() {
		for _, id := range certificateIDs {
			p.Pool.Exec(context.Background(), `DELETE FROM node_certificates WHERE id=$1::uuid`, id)
		}
	}()
	makeCert := func(n, domain, environment string) string {
		t.Helper()
		c, e := p.CreateNodeCertificate(ctx, n, domain, "letsencrypt", "http-01", environment, nil, true)
		check(e)
		certificateIDs = append(certificateIDs, c.ID)
		_, e = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_before=now()-interval '1 day',not_after=now()+interval '60 days' WHERE id=$1::uuid`, c.ID)
		check(e)
		return c.ID
	}
	cert := makeCert(node, "codex-tls.example.test", "production")
	staging := makeCert(node, "codex-tls-staging.example.test", "staging")
	foreign := makeCert(otherNode, "codex-tls-foreign.example.test", "production")
	address := "codex-tls.example.test"
	port := 18443
	s, err := p.CreateVPNService(ctx, node, "CODEX-TLS-INTEGRATION", "trojan", "0.0.0.0", port, "tcp", "tls", &address, &port)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM vpn_services WHERE id=$1::uuid`, s.ID)
	for _, bad := range []string{staging, foreign} {
		if _, _, err = p.ConfigureVPNServiceTLS(ctx, s.ID, bad); !errors.Is(err, ErrVPNServiceTLSInvalid) {
			t.Fatal("untrusted or cross-node certificate accepted")
		}
	}
	_, _, err = p.ConfigureVPNServiceTLS(ctx, s.ID, cert)
	check(err)
	if err = p.ArchiveNodeCertificate(ctx, cert); !errors.Is(err, ErrCertificateInUse) {
		t.Fatal("in-use certificate archived")
	}
	state, err := p.SetVPNServiceEnabledAndRebuild(ctx, s.ID, true)
	check(err)
	found := false
	for _, svc := range state.Services {
		if svc.ID == s.ID {
			found = svc.TLS != nil && svc.TLS.CertificateID == cert && svc.TLS.ServerName == address && svc.TLS.KeyFile == ""
		}
	}
	if !found {
		t.Fatal("TLS metadata missing from desired state")
	}
	_, g, err := p.ConfigureVPNServiceTLS(ctx, s.ID, cert)
	check(err)
	if g != 0 {
		t.Fatal("idempotent certificate bind rebuilt")
	}
	client, err := p.CreateVPNClient(ctx, s.TenantID, "CODEX-TLS-CLIENT", nil)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM vpn_clients WHERE id=$1::uuid`, client.ID)
	_, err = p.AttachVPNClientAndRebuild(ctx, s.ID, client.ID)
	check(err)
	connections, err := p.ListVPNClientConnections(ctx, client.ID)
	check(err)
	if len(connections) != 1 || connections[0].Security != "tls" || connections[0].Protocol != "trojan" || connections[0].ServerName != address {
		t.Fatal("TLS subscription connection missing")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='renewing' WHERE id=$1::uuid`, cert)
	check(err)
	_, err = p.RebuildNodeDesiredState(ctx, node)
	check(err)
	_, err = p.SetVPNServiceEnabledAndRebuild(ctx, s.ID, false)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.15' WHERE id=$1::uuid`, node)
	check(err)
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, s.ID, true); err == nil {
		t.Fatal("old agent allowed TLS service")
	}
	service, err := p.GetVPNService(ctx, s.ID)
	check(err)
	if service.Enabled {
		t.Fatal("failed rebuild left service enabled")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.16' WHERE id=$1::uuid`, node)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_after=now()-interval '1 minute' WHERE id=$1::uuid`, cert)
	check(err)
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, s.ID, true); err == nil {
		t.Fatal("expired certificate enabled")
	}
	service, err = p.GetVPNService(ctx, s.ID)
	check(err)
	if service.Enabled {
		t.Fatal("expired certificate mutation committed")
	}
}
