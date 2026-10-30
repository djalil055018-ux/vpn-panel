//go:build integration

package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func TestCertificateManagementIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated test database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout(30*time.Second))
	defer cancel()
	p, err := NewPostgres(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	defer p.Close()
	var dbName string
	if err = p.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil || !strings.HasPrefix(dbName, "vpn_codex_test_") {
		t.Fatal("refusing non-test database")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, fixtureServices := nativeAccessFixture(t, ctx, p)
	var fixtureNode string
	check(p.Pool.QueryRow(ctx, `SELECT node_id::text FROM vpn_services WHERE id=$1::uuid`, fixtureServices[0]).Scan(&fixtureNode))
	cert, err := p.CreateNodeCertificate(ctx, fixtureNode, "codex-renewal.example.test", "letsencrypt", "http-01", "staging", nil, true)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM node_certificates WHERE id=$1::uuid`, cert.ID)
	_, err = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_before=now()-interval '60 days',not_after=now()+interval '10 days' WHERE id=$1::uuid`, cert.ID)
	check(err)
	check(p.SetCertificateAutoRenew(ctx, cert.ID, false))
	n, err := p.QueueDueCertificateRenewals(ctx)
	check(err)
	if n != 0 {
		t.Fatal("disabled auto-renew queued work")
	}
	check(p.SetCertificateAutoRenew(ctx, cert.ID, true))
	n, err = p.QueueDueCertificateRenewals(ctx)
	check(err)
	if n != 1 {
		t.Fatalf("due renewal queue count = %d", n)
	}
	n, err = p.QueueDueCertificateRenewals(ctx)
	check(err)
	if n != 0 {
		t.Fatal("duplicate renewal queued")
	}
	if err = p.ArchiveNodeCertificate(ctx, cert.ID); !errors.Is(err, ErrCertificateJobExists) {
		t.Fatal("archive allowed with active job")
	}
	jobs, err := p.ListCertificateJobs(ctx, cert.ID)
	check(err)
	if len(jobs) != 1 || jobs[0].Operation != "renew" {
		t.Fatal("job history incorrect")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE certificate_jobs SET status='failed',completed_at=now() WHERE certificate_id=$1::uuid`, cert.ID)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='active' WHERE id=$1::uuid`, cert.ID)
	check(err)
	n, err = p.QueueDueCertificateRenewals(ctx)
	check(err)
	if n != 0 {
		t.Fatal("renewal retry ignored six-hour backoff")
	}
	check(p.ArchiveNodeCertificate(ctx, cert.ID))
	archived, err := p.GetNodeCertificate(ctx, cert.ID)
	check(err)
	if archived.AutoRenew || archived.Status != "revoked" {
		t.Fatal("archive did not disable management")
	}
	check(p.ArchiveNodeCertificate(ctx, cert.ID))
	if err = p.SetCertificateAutoRenew(ctx, cert.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatal("archived certificate could enable auto-renew")
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.35' WHERE id=$1::uuid`, cert.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err = p.QueueCertificateDeletion(ctx, cert.ID, cert.Domain); !errors.Is(err, ErrCertificateJobInvalidState) {
		t.Fatal("old agent accepted certificate deletion", err)
	}
	if _, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.36' WHERE id=$1::uuid`, cert.NodeID); err != nil {
		t.Fatal(err)
	}
	deletedCert, err := p.CreateNodeCertificate(ctx, cert.NodeID, "codex-delete.example.test", "letsencrypt", "http-01", "staging", nil, false)
	check(err)
	defer p.Pool.Exec(context.Background(), `DELETE FROM node_certificates WHERE id=$1::uuid`, deletedCert.ID)
	job, err := p.QueueCertificateDeletion(ctx, deletedCert.ID, deletedCert.Domain)
	check(err)
	if _, err = p.QueueCertificateDeletion(ctx, deletedCert.ID, deletedCert.Domain); !errors.Is(err, ErrCertificateJobInvalidState) {
		t.Fatal("duplicate deletion accepted", err)
	}
	work, err := p.ClaimCertificateJob(ctx, deletedCert.NodeID, "11111111-1111-4111-8111-111111111111", "synthetic-delete-lease", time.Minute)
	check(err)
	if work.JobID != job.ID || work.Operation != "delete" {
		t.Fatal("wrong certificate job claimed")
	}
	check(p.CompleteCertificateJob(ctx, deletedCert.NodeID, model.CertificateJobResult{JobID: job.ID, CertificateID: deletedCert.ID, Success: true}, "synthetic-delete-lease"))
	removed, err := p.ListNodeCertificates(ctx, deletedCert.NodeID)
	check(err)
	for _, item := range removed {
		if item.ID == deletedCert.ID {
			t.Fatal("deleted certificate remains in active listing")
		}
	}
	if _, err = p.CreateNodeCertificate(ctx, deletedCert.NodeID, deletedCert.Domain, "letsencrypt", "http-01", "staging", nil, false); err != nil {
		t.Fatal("deleted domain could not be reused", err)
	}
}
