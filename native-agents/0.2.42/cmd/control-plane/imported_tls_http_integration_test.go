//go:build integration

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/nodeadoption"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

func TestImportedTLSHTTPIntegration(t *testing.T) {
	dsn := os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	db, e := store.NewPostgres(ctx, dsn)
	if e != nil {
		t.Fatal("test database unavailable")
	}
	defer db.Close()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var name string
	check(db.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&name))
	if !strings.HasPrefix(name, "vpn_codex_test_delete_") {
		t.Fatal("refusing non-test database")
	}
	tenant, e := db.CreateTenant(ctx, "TLS HTTP fixture")
	check(e)
	node, e := db.CreateNodeForRuntime(ctx, tenant.ID, "TLS HTTP unused node", security.HashToken("synthetic-tls-http-bootstrap"), "xray")
	check(e)
	raw, e := os.ReadFile("../../internal/remnawave/testdata/inventory.json")
	check(e)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	inv["source_origin"] = "https://tls-http.example.test"
	inv["users"] = []any{}
	inv["devices"] = []any{}
	inv["verification"].(map[string]any)["source_total"] = 0
	inv["verification"].(map[string]any)["unique_user_ids"] = 0
	source, profile, inbound := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	in := map[string]any{"tag": "hys", "protocol": "hysteria", "listen": "0.0.0.0", "port": 443, "settings": map[string]any{"clients": []any{}, "version": 2}, "streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2}, "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": "/source/cert.pem", "keyFile": "/source/key.pem"}}}}}
	meta := []any{map[string]any{"uuid": inbound, "profileUuid": profile, "tag": "hys", "type": "hysteria", "network": "hysteria", "security": "tls", "port": 443, "rawInbound": in}}
	inv["nodes"] = []any{map[string]any{"uuid": source, "isDisabled": false, "activePluginUuid": nil, "proxyUrl": nil, "consumptionMultiplier": 1, "nodeConsumptionMultiplier": 1, "configProfile": map[string]any{"activeConfigProfileUuid": profile, "activeInbounds": meta}}}
	inv["config_profiles"] = map[string]any{"configProfiles": []any{map[string]any{"uuid": profile, "config": map[string]any{"inbounds": []any{in}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}}, "inbounds": meta, "nodes": []any{map[string]any{"uuid": source}}}}}
	raw, e = json.Marshal(inv)
	check(e)
	_, report, e := remnawave.Parse(raw)
	check(e)
	imported, _, e := db.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(e)
	// Only this isolated test process trusts the synthetic CA; production keeps
	// the normal system trust store and never accepts a caller-supplied root.
	now := time.Now()
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(e)
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(e)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic HTTP CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	check(e)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"tls-http.example.test"}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: root.NotBefore, NotAfter: now.Add(10 * 24 * time.Hour)}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	check(e)
	tmp := t.TempDir()
	rootPath := filepath.Join(tmp, "root.pem")
	check(os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0600))
	t.Setenv("SSL_CERT_FILE", rootPath)
	t.Setenv("SSL_CERT_DIR", tmp)
	chain := strings.Repeat("\n", 9<<10) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	privateDER, e := x509.MarshalPKCS8PrivateKey(leafKey)
	check(e)
	check(os.WriteFile(filepath.Join(tmp, "cert.pem"), []byte(chain), 0600))
	check(os.WriteFile(filepath.Join(tmp, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600))
	host, e := os.Hostname()
	check(e)
	planningRequest := nodeadoption.PlanningRequest{Version: 1, TenantID: tenant.ID, ImportID: imported.ID, NodeID: node.ID, SourceNodeID: source, ReviewedSHA256: report.SHA256, ExpectedHostname: host, Mounts: []nodeadoption.Mount{{ContainerPath: "/source", HostPath: tmp}}, TLSDomains: []nodeadoption.Domain{{InboundTag: "hys", Domain: "tls-http.example.test"}}}
	planBundle, e := nodeadoption.PlanInspection(planningRequest, raw)
	check(e)
	var localPlan nodeadoption.InspectionPlan
	check(nodeadoption.DecodePlan(planBundle.Files["inspection-plan.json"], &localPlan))
	inspection, e := nodeadoption.Inspect(localPlan, planBundle.Files["source-config.json"])
	check(e)
	var body store.ImportedTLSRequest
	requests := 0
	for name, data := range inspection.PublicBundle().Files {
		if strings.HasPrefix(name, "prepare-tls/") {
			requests++
			check(nodeadoption.DecodePlan(data, &body))
		}
	}
	if requests != 1 || body.AdoptionSHA256 != inspection.MaterialSHA256 {
		t.Fatal("node inspection did not produce exact owner TLS request")
	}
	wire, e := json.Marshal(body)
	check(e)
	if len(wire) <= 16384 {
		t.Fatal("large-chain HTTP fixture is too small")
	}
	app := &application{store: db, adminToken: "synthetic-http-tls-owner"}
	mux := http.NewServeMux()
	app.registerRemnawaveRoutes(mux)
	app.registerXrayOnboardingRoutes(mux)
	app.registerCertificateManagementRoutes(mux)
	mux.HandleFunc("POST /api/v1/certificates/{id}/renew", app.requireAdmin(app.renewCertificate))
	request := func(method, path string, payload []byte, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(string(payload)))
		r.Header.Set("Authorization", "Bearer "+app.adminToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Remnawave-Mode", "prepare-held-tls")
		if strings.HasSuffix(path, "/prepare-xray-node") {
			r.Header.Set("X-Remnawave-Mode", "prepare-held-xray")
		}
		r.Header.Set("X-Reviewed-Inventory-SHA256", report.SHA256)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("isolated HTTP status %d, want %d", w.Code, want)
		}
		if strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(w.Body.String(), app.adminToken) {
			t.Fatal("response echoed sensitive request material")
		}
		return w
	}
	path := "/api/v1/remnawave/imports/" + imported.ID + "/prepare-tls"
	first := request("POST", path, wire, 200)
	second := request("POST", path, wire, 200)
	if first.Body.String() != second.Body.String() || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("HTTP retry or cache policy differs")
	}
	var out struct {
		Preparation   store.ImportedTLSPreparation `json:"preparation"`
		PhysicalProof string                       `json:"physical_proof"`
		CutoverReady  bool                         `json:"cutover_ready"`
	}
	check(json.Unmarshal(first.Body.Bytes(), &out))
	if out.Preparation.State != "prepared" || out.CutoverReady || out.PhysicalProof != "owner_attestation" || out.Preparation.AdoptionSHA256 != body.AdoptionSHA256 {
		t.Fatal("preparation falsely claimed activation or independent proof")
	}
	responses := append([]byte("["), first.Body.Bytes()...)
	responses = append(responses, ']')
	certificates, e := nodeadoption.DecodeCertificateResponses(responses)
	check(e)
	preparationBundle, e := nodeadoption.PlanPreparation(planningRequest, raw, *inspection, certificates)
	check(e)
	nativeResponse := request("POST", "/api/v1/remnawave/imports/"+imported.ID+"/prepare-xray-node", preparationBundle.Files["prepare-xray-node.json"], 200)
	// Registering an Agent is safe while held. The ordinary initialization
	// button must not publish an empty generation and invalidate preparation.
	_, e = db.BootstrapAgentForRuntime(ctx, security.HashToken("synthetic-tls-http-bootstrap"), security.HashToken("synthetic-tls-http-agent"), "0.2.31", "ubuntu", "24.04", "amd64", "xray")
	check(e)
	release, e := db.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.9.9", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/imported-onboarding.zip", SHA256: strings.Repeat("a", 64), Channel: "testing"})
	check(e)
	check(db.ApproveCoreRelease(ctx, release.ID))
	for i := 0; i < 2; i++ {
		blocked := request("POST", "/api/v1/nodes/"+node.ID+"/initialize-xray", []byte(`{}`), 409)
		if !strings.Contains(blocked.Body.String(), "adoption workflow") {
			t.Fatal("imported onboarding conflict has no actionable explanation")
		}
	}
	again := request("POST", "/api/v1/remnawave/imports/"+imported.ID+"/prepare-xray-node", preparationBundle.Files["prepare-xray-node.json"], 200)
	if again.Body.String() != nativeResponse.Body.String() {
		t.Fatal("blocked initialization changed prepared node identities")
	}
	var generation int64
	var deploymentCount int
	check(db.Pool.QueryRow(ctx, `SELECT desired_generation,(SELECT count(*) FROM deployments WHERE node_id=$1::uuid) FROM nodes WHERE id=$1::uuid`, node.ID).Scan(&generation, &deploymentCount))
	if generation != 0 || deploymentCount != 0 {
		t.Fatal("ordinary initialization published an imported runtime")
	}
	var native nodeadoption.Preparation
	check(nodeadoption.DecodePlan(nativeResponse.Body.Bytes(), &native))
	stageBundle, e := nodeadoption.PlanStage(planningRequest, raw, *inspection, native, certificates)
	check(e)
	var stagePlan nodeadoption.StagePlan
	check(nodeadoption.DecodePlan(stageBundle.Files["stage-plan.json"], &stagePlan))
	privateBundle, e := nodeadoption.Stage(stagePlan, stageBundle.Files["source-config.json"])
	check(e)
	result, e := nodeadoption.Publish(filepath.Join(tmp, "staged"), privateBundle)
	check(e)
	if result.CutoverReady || result.MaterialSHA256 != inspection.MaterialSHA256 {
		t.Fatal("staged result claims activation or loses attestation")
	}
	request("PATCH", "/api/v1/certificates/"+out.Preparation.CertificateID, []byte(`{"auto_renew":true}`), 409)
	request("POST", "/api/v1/certificates/"+out.Preparation.CertificateID+"/renew", []byte(`{}`), 409)
	body.Domain = "wrong.example.test"
	wire, e = json.Marshal(body)
	check(e)
	request("POST", path, wire, 409)
	var count int
	check(db.Pool.QueryRow(ctx, `SELECT count(*) FROM certificate_jobs`).Scan(&count))
	if count != 0 {
		t.Fatal("held HTTP request queued a certificate job")
	}
	check(db.Pool.QueryRow(ctx, `SELECT count(*) FROM desired_states WHERE node_id=$1::uuid`, node.ID).Scan(&count))
	if count != 0 {
		t.Fatal("TLS preparation changed runtime")
	}
}
