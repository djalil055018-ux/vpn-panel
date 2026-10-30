//go:build integration && linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
	"vpn-platform/internal/core/hysteria"
	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/store"
)

// This opt-in suite runs actual CP handlers, PostgreSQL, the pinned agent daemon
// and native QUIC client/server. An independent host timer owns cleanup, including
// dropping the uniquely named database. TLS is a local fixture, not an ACME proof.
func TestHysteriaRealControlPlaneNative(t *testing.T) {
	if os.Getenv("HYSTERIA_REAL_CP_AGENT") != "1" {
		t.Skip("requires independently armed real-CP host guard")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal("fixture operation failed", err)
		}
	}
	guardPath := os.Getenv("HYSTERIA_NATIVE_AGENT_GUARD")
	match := regexp.MustCompile(`^/root/vpn-hysteria-agent-e2e-([0-9a-f]{16})/guard\.json$`).FindStringSubmatch(guardPath)
	if match == nil {
		t.Fatal("guard identity refused")
	}
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(guardPath), 0700}, {guardPath, 0600}} {
		info, err := os.Lstat(entry.path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != entry.mode {
			t.Fatal("private guard unsafe")
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			t.Fatal("guard owner refused")
		}
	}
	var guard struct {
		Base, Suite, Database, Timer string
		Expires                      time.Time
	}
	raw, err := os.ReadFile(guardPath)
	check(err)
	check(json.Unmarshal(raw, &guard))
	if guard.Suite != "real-cp" || guard.Database != "vpn_codex_test_hys_real_"+match[1] || guard.Base != "/opt/vpn-hysteria-agent-e2e-"+match[1]+"/data" || guard.Timer != "vpn-hysteria-agent-e2e-"+match[1]+".timer" || time.Until(guard.Expires) < 4*time.Minute {
		t.Fatal("guard scope or expiry refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	check(exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", guard.Timer).Run())
	for _, path := range []string{"/usr/local/bin/vpn-node-agent", "/etc/vpn-platform/node-agent.env", "/etc/systemd/system/vpn-platform-node-agent.service", "/etc/systemd/system/vpn-platform-hysteria.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("existing node installation refused")
		}
	}
	db, err := store.NewPostgres(ctx, os.Getenv("VPN_ACCESS_PLAN_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("private clone unavailable")
	}
	defer db.Close()
	var database string
	if db.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database) != nil || database != guard.Database {
		t.Fatal("database outside guard refused")
	}
	base, fixture := guard.Base, filepath.Dir(guard.Base)
	tenant, err := db.CreateTenant(ctx, "CODEX-HYS-REAL-"+match[1])
	check(err)
	const bootstrap = "real-cp-native-fixture-bootstrap"
	node, err := db.CreateNodeForRuntime(ctx, tenant.ID, "CODEX-HYS-REAL", security.HashToken(bootstrap), "hysteria2")
	check(err)
	app := &application{store: db, adminToken: "real-cp-native-fixture-admin"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", app.healthz)
	mux.HandleFunc("POST /api/v1/agent/register", app.registerAgent)
	app.registerAgentCapabilityRoutes(mux)
	app.registerHysteriaOnboardingRoutes(mux)
	app.registerAccessPlanRoutes(mux)
	app.registerTLSServiceRoutes(mux)
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /api/v1/agent/status", app.agentSelfStatus},
		{"GET /api/v1/agent/assignment", app.agentAssignment},
		{"POST /api/v1/agent/execution/claim", app.agentExecutionClaim},
		{"POST /api/v1/agent/execution/renew", app.agentExecutionRenew},
		{"POST /api/v1/agent/execution/fence-ack", app.agentExecutionFenceAck},
		{"POST /api/v1/agent/deployment-status", app.agentDeploymentStatus},
		{"POST /api/v1/agent/health", app.agentHealth},
		{"POST /api/v1/agent/traffic", app.receiveTrafficDelivery},
		{"POST /api/v1/agent/certificate-jobs/claim", app.agentCertificateJobClaim},
		{"POST /api/v1/agent/certificate-jobs/renew", app.agentCertificateJobRenew},
		{"POST /api/v1/agent/certificate-jobs/result", app.agentCertificateJobResult},
	} {
		mux.HandleFunc(route.pattern, app.requireAgent(route.handler))
	}
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"POST /api/v1/nodes/{id}/vpn-services", app.createVPNService},
		{"POST /api/v1/vpn-services/{id}/enable", app.enableVPNService},
		{"GET /api/v1/vpn-clients/{id}/connections", app.listVPNClientConnections},
	} {
		mux.HandleFunc(route.pattern, app.requireAdmin(route.handler))
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	// Stop before closing the real CP or DB, so the independent guard can retain
	// final local evidence even when a test assertion fails.
	defer func() { _ = exec.Command("systemctl", "stop", hysteria.ManagedAgentService).Run() }()
	request := func(method, path string, input any, status int, output any) {
		t.Helper()
		raw, err := json.Marshal(input)
		check(err)
		req, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(raw))
		check(err)
		req.Header.Set("Authorization", "Bearer "+app.adminToken)
		req.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(req)
		check(err)
		defer response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("CP %s %s status %d, expected %d", method, path, response.StatusCode, status)
		}
		if output != nil {
			check(json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output))
		}
	}
	await := func(label string, predicate func() bool) {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for ctx.Err() == nil && time.Now().Before(deadline) {
			if predicate() {
				t.Log(label + ": PASS")
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatal("native CP deadline: " + label)
	}
	currentGeneration := func() int64 {
		t.Helper()
		var generation int64
		check(db.Pool.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid`, node.ID).Scan(&generation))
		return generation
	}
	healthy := func(generation int64, after time.Time) bool {
		var ok bool
		version := model.HysteriaPinnedVersion
		if generation == 1 {
			version = ""
		} // Initial idle state has no running core.
		err := db.Pool.QueryRow(ctx, `SELECT n.desired_generation=$2 AND n.applied_generation=$2 AND h.applied_generation=$2 AND h.healthy AND h.core='hysteria2' AND h.core_version=$3 AND h.checked_at>$4 AND d.status='healthy' FROM nodes n JOIN node_health h ON h.node_id=n.id JOIN deployments d ON d.node_id=n.id AND d.generation=n.desired_generation WHERE n.id=$1::uuid`, node.ID, generation, version, after).Scan(&ok)
		return err == nil && ok
	}
	bootstrapFile := filepath.Join(fixture, "bootstrap")
	check(os.WriteFile(bootstrapFile, []byte(bootstrap), 0600))
	candidateRoot := "/opt/vpn-platform-candidates/hysteria2-v0.1"
	tool := filepath.Join(candidateRoot, "platform/scripts/vpn-node-tool.py")
	command := exec.CommandContext(ctx, "python3", tool, "install", "--data-dir", base, "--control-plane", server.URL, "--allow-http-test", "--artifact-file", filepath.Join(candidateRoot, "node-agent-candidate-0.2.25"), "--core", "hysteria2", "--bootstrap-token-file", bootstrapFile)
	out, err := command.CombinedOutput()
	check(os.WriteFile(filepath.Join(fixture, "tool-install.log"), out, 0600))
	if err != nil {
		t.Fatal("real CP node installation failed; private log retained")
	}
	identity, err := hysteria.ReadManagedAccount(ctx)
	check(err)
	raw, err = json.Marshal(identity)
	check(err)
	check(os.WriteFile(filepath.Join(filepath.Dir(guardPath), "created-account.json"), raw, 0600))
	t.Log("real capability inspection and one-shot bootstrap registration: PASS")
	destination := filepath.Join(base, "cores/hysteria2", model.HysteriaPinnedVersion, "hysteria")
	coreBinary, err := os.ReadFile(filepath.Join(candidateRoot, "hysteria-linux-amd64-v2.12.2"))
	check(err)
	check(os.MkdirAll(filepath.Dir(destination), 0755))
	check(os.WriteFile(destination, coreBinary, 0555))
	check(os.Chmod(destination, 0555))
	installer, err := hysteria.NewInstaller(base)
	check(err)
	_, err = installer.Install(ctx, model.CoreRelease{Type: "hysteria2", Version: model.HysteriaPinnedVersion, SHA256: model.HysteriaPinnedSHA256, DownloadURL: model.HysteriaPinnedDownloadURL})
	check(err)
	request("POST", "/api/v1/core-releases/hysteria2/import-reviewed", nil, 201, nil)
	request("POST", "/api/v1/core-releases/hysteria2/approve-reviewed", nil, 200, nil)
	start := time.Now()
	request("POST", "/api/v1/nodes/"+node.ID+"/initialize-hysteria", nil, 202, nil)
	await("real leased initial idle deployment", func() bool { return healthy(1, start) })
	cert, err := db.CreateNodeCertificate(ctx, node.ID, "tls-probe.invalid", "letsencrypt", "http-01", "production", nil, true)
	check(err)
	// Explicit fixture metadata/material; no external certificate issuance occurs.
	_, err = db.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_before=now()-interval '1 hour',not_after=now()+interval '1 hour' WHERE id=$1::uuid`, cert.ID)
	check(err)
	certRoot := filepath.Join(base, "certificates", cert.ID)
	versionDir := filepath.Join(certRoot, "versions/one")
	check(os.MkdirAll(versionDir, 0700))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cert.Domain}, DNSNames: []string{cert.Domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	check(err)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	check(err)
	check(os.WriteFile(filepath.Join(versionDir, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644))
	check(os.WriteFile(filepath.Join(versionDir, "private.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600))
	check(os.Symlink("versions/one", filepath.Join(certRoot, "current")))
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	check(err)
	port := listener.LocalAddr().(*net.UDPAddr).Port
	check(listener.Close())
	var service model.VPNService
	request("POST", "/api/v1/nodes/"+node.ID+"/vpn-services", map[string]any{"name": "Native Hys", "protocol": "hysteria2", "listen": "127.0.0.1", "port": port, "transport": "udp", "security": "tls", "public_address": "127.0.0.1", "public_port": port}, 201, &service)
	request("PUT", "/api/v1/vpn-services/"+service.ID+"/tls", map[string]string{"certificate_id": cert.ID}, 200, nil)
	start = time.Now()
	request("POST", "/api/v1/vpn-services/"+service.ID+"/enable", nil, 202, nil)
	generation := currentGeneration()
	await("TLS listener with no grants", func() bool { return healthy(generation, start) })
	stats, _, err := hysteria.OpenStoredTrafficSource(base, hysteria.ManagedService, false)
	check(err)
	system, err := hysteria.NewSystemdRuntime(hysteria.ManagedService, stats)
	check(err)
	initialEpoch, err := system.Invocation(ctx)
	check(err)
	var planA, planB model.VPNAccessPlan
	request("POST", "/api/v1/tenants/"+tenant.ID+"/access-plans", map[string]string{"name": "Native A", "code": "native-a"}, 201, &planA)
	request("POST", "/api/v1/tenants/"+tenant.ID+"/access-plans", map[string]string{"name": "Native B", "code": "native-b"}, 201, &planB)
	for _, plan := range []model.VPNAccessPlan{planA, planB} {
		request("POST", "/api/v1/access-plans/"+plan.ID+"/services/"+service.ID, nil, 200, nil)
	}
	clientA, err := db.CreateVPNClient(ctx, tenant.ID, "Native A", nil)
	check(err)
	clientB, err := db.CreateVPNClient(ctx, tenant.ID, "Native B", nil)
	check(err)
	grant := func(plan, client string) {
		t.Helper()
		start = time.Now()
		request("POST", "/api/v1/access-plans/"+plan+"/clients/"+client, nil, 200, nil)
		generation = currentGeneration()
		await("API plan grant applied", func() bool { return healthy(generation, start) })
	}
	connection := func(client string, count int) *url.URL {
		t.Helper()
		var value struct {
			Connections []model.VPNClientConnection `json:"connections"`
		}
		request("GET", "/api/v1/vpn-clients/"+client+"/connections", nil, 200, &value)
		if len(value.Connections) != count {
			t.Fatal("subscription access count differs")
		}
		if count == 0 {
			return nil
		}
		u, err := url.Parse(value.Connections[0].URI)
		check(err)
		if u.Scheme != "hysteria2" || u.Query().Get("sni") != cert.Domain || u.Query().Get("insecure") != "0" || u.User == nil {
			t.Fatal("subscription URI contract differs")
		}
		return u
	}
	payload := strings.Repeat("real-cp-native-payload", 4096)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, payload) }))
	defer origin.Close()
	startClient := func(name string, uri *url.URL) *http.Client {
		t.Helper()
		socket, err := net.Listen("tcp4", "127.0.0.1:0")
		check(err)
		socks := socket.Addr().String()
		check(socket.Close())
		config := map[string]any{"server": uri.Host, "auth": uri.User.Username(), "tls": map[string]any{"sni": uri.Query().Get("sni"), "ca": filepath.Join(certRoot, "current/fullchain.pem")}, "socks5": map[string]any{"listen": socks}}
		raw, err := json.Marshal(config)
		check(err)
		path := filepath.Join(fixture, name+".json")
		check(os.WriteFile(path, raw, 0600))
		cmd := exec.CommandContext(ctx, destination, "client", "-c", path)
		log, err := os.OpenFile(filepath.Join(fixture, name+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		check(err)
		cmd.Stdout, cmd.Stderr = log, log
		check(cmd.Start())
		check(log.Close())
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("native client cleanup timeout")
			}
		})
		proxy, err := url.Parse("socks5://" + socks)
		check(err)
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: time.Second}
	}
	reaches := func(client *http.Client) bool {
		for i := 0; i < 6; i++ {
			response, err := client.Get(origin.URL)
			if err == nil {
				raw, _ := io.ReadAll(io.LimitReader(response.Body, int64(len(payload)+1)))
				response.Body.Close()
				if string(raw) == payload {
					return true
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		return false
	}
	connection(clientA.ID, 0)
	grant(planA.ID, clientA.ID)
	uriA := connection(clientA.ID, 1)
	activeA := startClient("active-a", uriA)
	if !reaches(activeA) {
		t.Fatal("API-granted A tunnel failed")
	}
	grant(planB.ID, clientB.ID)
	uriB := connection(clientB.ID, 1)
	activeB := startClient("active-b", uriB)
	if !reaches(activeB) {
		t.Fatal("API-granted B tunnel failed")
	}
	if epoch, err := system.Invocation(ctx); err != nil || epoch != initialEpoch {
		t.Fatal("grant addition restarted core")
	}
	await("native traffic accepted in real CP usage", func() bool {
		a, ea := db.VPNClientUsage(ctx, clientA.ID)
		b, eb := db.VPNClientUsage(ctx, clientB.ID)
		return ea == nil && eb == nil && a.UplinkBytes > 0 && b.UplinkBytes > 0 && a.DownlinkBytes >= int64(len(payload)) && b.DownlinkBytes >= int64(len(payload)) && a.ActiveIPs == nil && b.ActiveIPs == nil
	})
	start = time.Now()
	request("DELETE", "/api/v1/access-plans/"+planA.ID+"/clients/"+clientA.ID, nil, 200, nil)
	generation = currentGeneration()
	await("API revocation applied", func() bool { return healthy(generation, start) })
	connection(clientA.ID, 0)
	connection(clientB.ID, 1)
	if epoch, err := system.Invocation(ctx); err != nil || epoch == initialEpoch {
		t.Fatal("revocation did not replace core invocation")
	}
	if reaches(activeA) || reaches(startClient("new-revoked-a", uriA)) {
		t.Fatal("revoked A retained or regained tunnel")
	}
	// Revocation deliberately stops every old QUIC session. A retained credential
	// must establish a new tunnel; the standalone client process is not a reconnect manager.
	if !reaches(startClient("retained-after-revoke", uriB)) {
		t.Fatal("B cannot reconnect after A revocation")
	}
	beforeCrash, err := system.Invocation(ctx)
	check(err)
	beforeUsage, err := db.VPNClientUsage(ctx, clientB.ID)
	check(err)
	start = time.Now()
	check(exec.CommandContext(ctx, "systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", hysteria.ManagedAgentService).Run())
	await("real CP authority and daemon crash recovery", func() bool {
		epoch, err := system.Invocation(ctx)
		return err == nil && epoch != beforeCrash && healthy(generation, start)
	})
	if !reaches(startClient("retained-after-crash", uriB)) {
		t.Fatal("B failed after crash")
	}
	if reaches(startClient("revoked-after-crash", uriA)) {
		t.Fatal("crash restored revoked A")
	}
	await("post-crash traffic persisted without invented IP counts", func() bool {
		value, err := db.VPNClientUsage(ctx, clientB.ID)
		return err == nil && value.UsedBytes > beforeUsage.UsedBytes && value.ActiveIPs == nil
	})
	t.Log(fmt.Sprintf("real CP + pinned agent + native Hysteria: generation %d, grants, TLS tunnel, traffic, revocation, crash recovery PASS; certificate issuance excluded", generation))
}
