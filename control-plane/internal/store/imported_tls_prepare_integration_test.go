//go:build integration

package store

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
)

type importedTLSFixture struct {
	ctx                                                          context.Context
	p                                                            *Postgres
	tenant, node, importID, digest, source, otherSource, inbound string
	raw                                                          []byte
	req                                                          ImportedTLSRequest
	roots                                                        *x509.CertPool
}

func importedTLSFixtureFor(t *testing.T) importedTLSFixture {
	t.Helper()
	ctx, p := deletionStore(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, e := p.CreateTenant(ctx, "TLS "+t.Name())
	check(e)
	node, e := p.CreateNodeForRuntime(ctx, tenant.ID, "Unused TLS node", security.HashToken("synthetic-tls-bootstrap"), "xray")
	check(e)
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	check(e)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	inv["source_origin"] = "https://" + strings.ToLower(t.Name()) + ".example.test"
	inv["users"] = []any{}
	inv["devices"] = []any{}
	inv["verification"].(map[string]any)["source_total"] = 0
	inv["verification"].(map[string]any)["unique_user_ids"] = 0
	source, other, profile, inbound := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	in := map[string]any{"tag": "hys", "protocol": "hysteria", "listen": "0.0.0.0", "port": 443, "settings": map[string]any{"clients": []any{}, "version": 2}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2}, "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": "/source/cert.pem", "keyFile": "/source/key.pem"}}}}}
	meta := []any{map[string]any{"uuid": inbound, "profileUuid": profile, "tag": "hys", "type": "hysteria", "network": "hysteria", "security": "tls", "port": 443, "rawInbound": in}}
	nodes := []any{}
	refs := []any{}
	for _, id := range []string{source, other} {
		nodes = append(nodes, map[string]any{"uuid": id, "isDisabled": false, "activePluginUuid": nil, "proxyUrl": nil, "consumptionMultiplier": 1, "nodeConsumptionMultiplier": 1, "configProfile": map[string]any{"activeConfigProfileUuid": profile, "activeInbounds": meta}})
		refs = append(refs, map[string]any{"uuid": id})
	}
	inv["nodes"] = nodes
	inv["config_profiles"] = map[string]any{"configProfiles": []any{map[string]any{"uuid": profile, "config": map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}}, "inbounds": meta, "nodes": refs}}}
	raw, e = json.Marshal(inv)
	check(e)
	_, report, e := remnawave.Parse(raw)
	check(e)
	item, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(e)
	chain := importedTLSTestChain(t, "import.example.test", nil)
	req := ImportedTLSRequest{TenantID: tenant.ID, NodeID: node.ID, SourceNodeID: source, Domain: "import.example.test", FullchainPEM: chain.fullchain, AdoptionSHA256: strings.Repeat("a", 64)}
	return importedTLSFixture{ctx, p, tenant.ID, node.ID, item.ID, report.SHA256, source, other, inbound, raw, req, chain.roots}
}

func TestImportedTLSPreparationIntegration(t *testing.T) {
	f := importedTLSFixtureFor(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, ctx := range []context.Context{WithTenantPrincipal(f.ctx, model.TenantAPIToken{TenantID: f.tenant, Role: "operator"}), WithAdminPrincipal(f.ctx, model.AdminSession{Account: model.AdminAccount{Role: "admin"}}), WithAdminPrincipal(f.ctx, model.AdminSession{Account: model.AdminAccount{Role: "monitor"}})} {
		if _, e := f.p.prepareImportedTLS(ctx, f.importID, f.digest, f.req, f.roots); !errors.Is(e, ErrNotFound) {
			t.Fatal("non-owner prepared a certificate")
		}
	}
	if _, e := f.p.prepareImportedTLS(f.ctx, f.importID, strings.Repeat("0", 64), f.req, f.roots); !errors.Is(e, ErrRemnawaveReview) {
		t.Fatal("stale review accepted")
	}
	wrong := f.req
	wrong.TenantID = "00000000-0000-4000-8000-000000000001"
	if _, e := f.p.prepareImportedTLS(f.ctx, f.importID, f.digest, wrong, f.roots); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant request accepted")
	}
	invalid := f.req
	invalid.FullchainPEM += "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
	if _, e := f.p.prepareImportedTLS(f.ctx, f.importID, f.digest, invalid, f.roots); !errors.Is(e, ErrImportedTLS) {
		t.Fatal("private key accepted")
	}
	var wg sync.WaitGroup
	outs := make(chan ImportedTLSPreparation, 4)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, e := f.p.prepareImportedTLS(f.ctx, f.importID, f.digest, f.req, f.roots)
			outs <- o
			errs <- e
		}()
	}
	wg.Wait()
	close(outs)
	close(errs)
	for e := range errs {
		check(e)
	}
	var first ImportedTLSPreparation
	for o := range outs {
		if first.CertificateID == "" {
			first = o
		} else if !reflect.DeepEqual(first, o) {
			t.Fatal("concurrent replay changed identity")
		}
	}
	if first.State != "prepared" || first.InventorySHA256 != f.digest || first.ReviewedSHA256 != f.digest || first.AdoptionSHA256 != f.req.AdoptionSHA256 {
		t.Fatal("incorrect preparation provenance")
	}
	var count int
	check(f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM imported_tls_certificates WHERE node_id=$1::uuid`, f.node).Scan(&count))
	if count != 1 {
		t.Fatal("duplicate imported certificates")
	}
	check(f.p.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE node_id=$1::uuid AND event_type='imported_tls.prepared'`, f.node).Scan(&count))
	if count != 1 {
		t.Fatal("replay duplicated audit")
	}
	cert, e := f.p.GetNodeCertificate(f.ctx, first.CertificateID)
	check(e)
	if cert.AutoRenew || cert.Status != "active" || cert.Domain != f.req.Domain || cert.CertificateRef != "certificates/"+cert.ID {
		t.Fatal("wrong native certificate preparation")
	}
	for _, operation := range []string{"issue", "renew"} {
		if _, e = f.p.QueueCertificateJob(f.ctx, cert.ID, operation); !errors.Is(e, ErrCertificateJobInvalidState) {
			t.Fatal("held operation queued")
		}
	}
	if e = f.p.SetCertificateAutoRenew(f.ctx, cert.ID, true); !errors.Is(e, ErrCertificateJobInvalidState) {
		t.Fatal("held automatic renewal enabled")
	}
	check(f.p.SetCertificateAutoRenew(f.ctx, cert.ID, false))
	due, e := f.p.QueueDueCertificateRenewals(f.ctx)
	check(e)
	if due != 0 {
		t.Fatal("held renewal scheduled")
	}
	for _, q := range []string{`UPDATE node_certificates SET auto_renew=true WHERE id=$1::uuid`, `UPDATE node_certificates SET fingerprint_sha256=repeat('b',64) WHERE id=$1::uuid`, `UPDATE node_certificates SET domain='other.example.test' WHERE id=$1::uuid`, `INSERT INTO certificate_jobs(tenant_id,node_id,certificate_id,operation,status) SELECT tenant_id,node_id,id,'renew','pending' FROM node_certificates WHERE id=$1::uuid`} {
		if _, e = f.p.Pool.Exec(f.ctx, q, cert.ID); e == nil {
			t.Fatal("database bypassed held certificate fence")
		}
	}
	changed := f.req
	changed.AdoptionSHA256 = strings.Repeat("b", 64)
	if _, e = f.p.prepareImportedTLS(f.ctx, f.importID, f.digest, changed, f.roots); !errors.Is(e, ErrImportedTLS) {
		t.Fatal("attestation replacement accepted")
	}
	tls := []XrayProfileTLSAssignment{{SourceInboundID: f.inbound, CertificateID: cert.ID}}
	if _, e = f.p.PrepareXrayProfile(f.ctx, f.tenant, f.importID, f.node, f.otherSource, f.digest, tls); !errors.Is(e, ErrVPNServiceTLSInvalid) {
		t.Fatal("certificate assigned to another source node")
	}
	profile, e := f.p.PrepareXrayProfile(f.ctx, f.tenant, f.importID, f.node, f.source, f.digest, tls)
	check(e)
	if profile.State != "prepared" || len(profile.Services) != 1 {
		t.Fatal("TLS profile preparation failed")
	}
	if e = f.p.ArchiveNodeCertificate(f.ctx, cert.ID); !errors.Is(e, ErrCertificateInUse) {
		t.Fatal("assigned certificate archived")
	}
	if _, e = f.p.QueueCertificateJob(f.ctx, cert.ID, "renew"); !errors.Is(e, ErrCertificateJobInvalidState) {
		t.Fatal("prepared profile released renewal")
	}
	// Explicitly synthetic activation, solely to prove the post-adoption gate opens.
	_, e = f.p.Pool.Exec(f.ctx, `UPDATE node_xray_profiles SET state='active',adoption_sha256=$2,activated_at=now() WHERE node_id=$1::uuid`, f.node, f.req.AdoptionSHA256)
	check(e)
	check(f.p.SetCertificateAutoRenew(f.ctx, cert.ID, true))
	due, e = f.p.QueueDueCertificateRenewals(f.ctx)
	check(e)
	if due != 1 {
		t.Fatal("matching active profile did not permit renewal")
	}
	due, e = f.p.QueueDueCertificateRenewals(f.ctx)
	check(e)
	if due != 0 {
		t.Fatal("duplicate renewal scheduled")
	}
	var generation int64
	check(f.p.Pool.QueryRow(f.ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, f.node).Scan(&generation))
	if generation != 0 {
		t.Fatal("TLS preparation changed runtime generation")
	}
}

func TestImportedTLSPreparationConflictsIntegration(t *testing.T) {
	f := importedTLSFixtureFor(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	first, e := f.p.prepareImportedTLS(f.ctx, f.importID, f.digest, f.req, f.roots)
	check(e)
	// A later user-only revision preserves the certificate's original provenance.
	var inv map[string]any
	check(json.Unmarshal(f.raw, &inv))
	inv["captured_at"] = "2026-09-26T00:00:00Z"
	next, e := json.Marshal(inv)
	check(e)
	_, r, e := remnawave.Parse(next)
	check(e)
	_, e = f.p.ApplyRemnawaveHeldDelta(f.ctx, f.importID, f.tenant, f.digest, r.SHA256, next)
	check(e)
	again, e := f.p.prepareImportedTLS(f.ctx, f.importID, r.SHA256, f.req, f.roots)
	check(e)
	if again.CertificateID != first.CertificateID || again.InventorySHA256 != f.digest || again.ReviewedSHA256 != r.SHA256 || again.AdoptionSHA256 != first.AdoptionSHA256 {
		t.Fatal("later review rewrote certificate provenance")
	}
	newNode := func(name, runtime string) string {
		n, e := f.p.CreateNodeForRuntime(f.ctx, f.tenant, name, security.HashToken("synthetic-"+name), runtime)
		check(e)
		return n.ID
	}
	foreign, e := f.p.CreateTenant(f.ctx, "Foreign TLS tenant")
	check(e)
	foreignNode, e := f.p.CreateNodeForRuntime(f.ctx, foreign.ID, "Foreign TLS node", security.HashToken("synthetic-foreign-tls"), "xray")
	check(e)
	for label, node := range map[string]string{"native-other-runtime": newNode("PPTP TLS candidate", "pptp"), "foreign-node": foreignNode.ID, "retired": newNode("Retired TLS candidate", "xray"), "used": newNode("Used TLS candidate", "xray")} {
		req := f.req
		req.NodeID = node
		if label == "retired" {
			_, e = f.p.DeleteNode(f.ctx, node, "Retired TLS candidate", true)
			check(e)
		}
		if label == "used" {
			_, e = f.p.Pool.Exec(f.ctx, `UPDATE nodes SET desired_generation=1 WHERE id=$1::uuid`, node)
			check(e)
		}
		if _, e = f.p.prepareImportedTLS(f.ctx, f.importID, r.SHA256, req, f.roots); e == nil {
			t.Fatal("unavailable node accepted: " + label)
		}
	}
	// An existing native certificate cannot be silently adopted or overwritten.
	nativeNode := newNode("Native certificate TLS candidate", "xray")
	native, e := f.p.CreateNodeCertificate(f.ctx, nativeNode, f.req.Domain, "letsencrypt", "http-01", "production", nil, false)
	check(e)
	req := f.req
	req.NodeID = nativeNode
	if _, e = f.p.prepareImportedTLS(f.ctx, f.importID, r.SHA256, req, f.roots); !errors.Is(e, ErrImportedTLS) {
		t.Fatal("existing native certificate overwritten")
	}
	unchanged, e := f.p.GetNodeCertificate(f.ctx, native.ID)
	check(e)
	if unchanged.Status != "draft" {
		t.Fatal("failed import changed native certificate")
	}
	check(f.p.SetCertificateAutoRenew(f.ctx, native.ID, true))
	job, e := f.p.QueueCertificateJob(f.ctx, native.ID, "issue")
	check(e)
	if job.Operation != "issue" {
		t.Fatal("native certificate workflow regressed")
	}
}
