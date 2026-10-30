//go:build linux

package hysteria

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

const nativeAgentNode = "99999999-9999-4999-8999-999999999999"
const nativeAgentTenant = "11111111-1111-4111-8111-111111111111"
const nativeAgentToken = "native-agent-fixture-permanent-token"
const nativeBootstrapToken = "native-agent-fixture-bootstrap-token"
const nativeLeaseToken = "native-agent-fixture-lease-token"

// This peer is deliberately isolated from production CP and has no real tokens.
// It validates the real daemon's registration/lease/report/traffic transitions;
// it is not a substitute for the separate real-CP API integration suite.
type nativeAgentPeer struct {
	mu                             sync.Mutex
	assignment                     model.AgentAssignment
	registered                     bool
	health                         model.HealthReport
	seen                           time.Time
	owner                          string
	claims, reports, registrations int
	inspections                    int
	epochs                         map[string]int64
	lastSequence                   int64
	bad                            bool
	failure                        string
}

func (p *nativeAgentPeer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	respond := func(value any) { _ = json.NewEncoder(w).Encode(value) }
	decode := func(value any) bool { return json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(value) == nil }
	if r.URL.Path == "/healthz" {
		respond(map[string]string{"service": "vpn-platform-control-plane", "version": "0.1.85"})
		return
	}
	if r.URL.Path == "/api/v1/agent/capabilities" {
		respond(map[string]any{"format": 1, "runtime_selection": true, "bootstrap_inspection": true, "traffic_address_availability": true, "runtimes": map[string]any{"hysteria2": map[string]any{"minimum_agent": "0.2.25", "provisioning": true}}})
		return
	}
	if r.URL.Path == "/api/v1/agent/bootstrap-info" {
		_, installed := os.Lstat("/usr/local/bin/vpn-node-agent")
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+nativeBootstrapToken || p.registered || !os.IsNotExist(installed) {
			p.bad = true
			w.WriteHeader(401)
			return
		}
		p.inspections++
		respond(map[string]string{"node_id": nativeAgentNode, "runtime_core": "hysteria2"})
		return
	}
	if r.URL.Path == "/api/v1/agent/register" {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+nativeBootstrapToken || p.registered {
			p.bad = true
			w.WriteHeader(403)
			return
		}
		var registration map[string]string
		if !decode(&registration) || registration["agent_version"] != "0.2.27" || registration["runtime_core"] != "hysteria2" {
			p.bad = true
			w.WriteHeader(400)
			return
		}
		p.registered = true
		p.registrations++
		respond(map[string]string{"node_id": nativeAgentNode, "tenant_id": nativeAgentTenant, "agent_token": nativeAgentToken, "runtime_core": "hysteria2"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+nativeAgentToken {
		p.bad = true
		w.WriteHeader(401)
		return
	}
	switch r.URL.Path {
	case "/api/v1/agent/status":
		respond(map[string]any{"node_id": nativeAgentNode, "registered": p.registered, "online": time.Since(p.seen) < 15*time.Second, "agent_version": p.health.AgentVersion, "health_fresh": time.Since(p.seen) < 15*time.Second, "health_checked_at": p.health.CheckedAt, "desired_generation": p.assignment.DesiredState.Generation, "applied_generation": p.health.AppliedGeneration, "healthy": p.health.Healthy, "runtime_core": "hysteria2"})
	case "/api/v1/agent/assignment":
		if p.assignment.DesiredState.Generation == 0 {
			w.WriteHeader(204)
		} else {
			respond(p.assignment)
		}
	case "/api/v1/agent/execution/claim":
		var request model.ExecutionLeaseClaimRequest
		if !decode(&request) || request.Execution != p.assignment.Execution || request.OwnerInstanceID == "" || (p.assignment.DeploymentStatus != "pending" && p.assignment.DeploymentStatus != "applying") {
			p.bad = true
			w.WriteHeader(409)
			return
		}
		p.owner = request.OwnerInstanceID
		p.claims++
		respond(model.ExecutionLeaseGrant{LeaseToken: nativeLeaseToken, LeaseExpiresAt: time.Now().Add(time.Minute), RenewAfterSeconds: 10})
	case "/api/v1/agent/execution/renew":
		var request model.ExecutionLeaseRenewRequest
		if !decode(&request) || request.Execution != p.assignment.Execution || request.OwnerInstanceID != p.owner || request.LeaseToken != nativeLeaseToken {
			p.bad = true
			w.WriteHeader(409)
			return
		}
		respond(model.ExecutionLeaseGrant{LeaseExpiresAt: time.Now().Add(time.Minute), RenewAfterSeconds: 10})
	case "/api/v1/agent/deployment-status":
		var report model.DeploymentReport
		if !decode(&report) || report.Generation != p.assignment.DesiredState.Generation || report.DeploymentID != p.assignment.Execution.DeploymentID || report.ExecutionID != p.assignment.Execution.ExecutionID || report.ExecutionEpoch != p.assignment.Execution.ExecutionEpoch || report.OwnerInstanceID != p.owner || report.LeaseToken != nativeLeaseToken {
			p.bad = true
			w.WriteHeader(409)
			return
		}
		switch report.Status {
		case "applying":
			p.assignment.DeploymentStatus = "applying"
		case "healthy":
			p.assignment.DeploymentStatus = "healthy"
			p.assignment.NodeAppliedGeneration = report.Generation
			p.assignment.AppliedCoreVersion = report.AppliedCoreVersion
			p.reports++
		default:
			p.bad = true
			p.failure = report.Status + ": " + report.ErrorMessage
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	case "/api/v1/agent/health":
		var health model.HealthReport
		if !decode(&health) || health.Core != "hysteria2" || health.AgentVersion != "0.2.27" {
			p.bad = true
			w.WriteHeader(400)
			return
		}
		p.health = health
		p.seen = time.Now()
		w.WriteHeader(204)
	case "/api/v1/agent/traffic":
		var value model.TrafficDelivery
		if !decode(&value) || value.Snapshot.Sequence <= 0 {
			p.bad = true
			w.WriteHeader(400)
			return
		}
		if value.Snapshot.Sequence < p.lastSequence {
			p.bad = true
			w.WriteHeader(400)
			return
		}
		p.lastSequence = value.Snapshot.Sequence
		var total int64
		for _, client := range value.Snapshot.Clients {
			if !client.ActiveIPsUnavailable || client.ActiveIPs != 0 {
				p.bad = true
				w.WriteHeader(400)
				return
			}
			total += client.Uplink + client.Downlink
		}
		if total > p.epochs[value.Snapshot.Epoch] {
			p.epochs[value.Snapshot.Epoch] = total
		}
		w.WriteHeader(204)
	case "/api/v1/agent/certificate-jobs/claim":
		w.WriteHeader(204)
	default:
		p.bad = true
		w.WriteHeader(404)
	}
}

func (p *nativeAgentPeer) assign(state model.DesiredState) {
	// Publishing a deep copy prevents later fixture edits from mutating a live
	// assignment while the daemon is reading it.
	raw, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	var cloned model.DesiredState
	if err = json.Unmarshal(raw, &cloned); err != nil {
		panic(err)
	}
	state = cloned
	p.mu.Lock()
	defer p.mu.Unlock()
	p.assignment = model.AgentAssignment{DesiredState: state, DeploymentStatus: "pending", NodeAppliedGeneration: p.health.AppliedGeneration, Execution: model.ExecutionAssignment{Generation: state.Generation, DeploymentID: fmt.Sprintf("22222222-2222-4222-8222-%012d", state.Generation), ExecutionID: fmt.Sprintf("33333333-3333-4333-8333-%012d", state.Generation), ExecutionEpoch: state.Generation}}
}
func (p *nativeAgentPeer) healthy(generation int64, after time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.bad && p.health.Healthy && p.health.AppliedGeneration == generation && p.seen.After(after) && p.assignment.DeploymentStatus == "healthy"
}

func nativeAwait(t *testing.T, ctx context.Context, label string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("native agent deadline: " + label)
}

func TestNativeAgentDaemonInstallRepairCrashRollback(t *testing.T) {
	if os.Getenv("HYSTERIA_NATIVE_AGENT") != "1" {
		t.Skip("requires explicitly armed host rollback guard")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	guardPath := os.Getenv("HYSTERIA_NATIVE_AGENT_GUARD")
	pattern := regexp.MustCompile(`^/root/vpn-hysteria-agent-e2e-([0-9a-f]{16})/guard\.json$`)
	match := pattern.FindStringSubmatch(guardPath)
	if match == nil {
		t.Fatal("guard path refused")
	}
	raw, err := readTLSFile(guardPath, 8192, 0600, -1)
	if err != nil {
		t.Fatal("private guard missing")
	}
	var guard struct {
		Base    string    `json:"base"`
		Expires time.Time `json:"expires"`
		Timer   string    `json:"timer"`
	}
	if json.Unmarshal(raw, &guard) != nil || guard.Base != "/opt/vpn-hysteria-agent-e2e-"+match[1]+"/data" || time.Until(guard.Expires) < 4*time.Minute || guard.Timer != "vpn-hysteria-agent-e2e-"+match[1]+".timer" {
		t.Fatal("guard identity/expiry refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", guard.Timer).Run() != nil {
		t.Fatal("host cleanup timer not armed")
	}
	for _, path := range []string{"/usr/local/bin/vpn-node-agent", "/etc/vpn-platform/node-agent.env", "/etc/systemd/system/vpn-platform-node-agent.service", "/etc/systemd/system/vpn-platform-hysteria.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("existing node lifecycle file; fixture refused")
		}
	}
	base := guard.Base
	fixture := filepath.Dir(base)
	if protectedDirectory(fixture, false) != nil {
		t.Fatal("fixture directory unsafe")
	}
	peer := &nativeAgentPeer{epochs: map[string]int64{}}
	server := httptest.NewServer(peer)
	defer server.Close()
	t.Cleanup(func() {
		peer.mu.Lock()
		defer peer.mu.Unlock()
		if peer.failure != "" {
			t.Log("synthetic CP deployment diagnostic: " + peer.failure)
		}
	})
	bootstrap := filepath.Join(fixture, "bootstrap")
	if os.WriteFile(bootstrap, []byte(nativeBootstrapToken), 0600) != nil {
		t.Fatal("bootstrap fixture failed")
	}
	candidate := "/opt/vpn-platform-candidates/protocol-catalog/bin/openvpn-agent"
	tool, _ := filepath.Abs("../../../scripts/vpn-node-tool.py")
	toolRun := func(command string, extra ...string) {
		t.Helper()
		args := []string{tool, command, "--data-dir", base, "--control-plane", server.URL, "--allow-http-test", "--artifact-file", candidate}
		args = append(args, extra...)
		cmd := exec.CommandContext(ctx, "python3", args...)
		out, err := cmd.CombinedOutput()
		_ = os.WriteFile(filepath.Join(fixture, "tool-"+command+".log"), out, 0600)
		if err != nil {
			t.Fatal("native node-tool " + command + " failed; private fixture log retained")
		}
	}
	toolRun("install", "--core", "hysteria2", "--bootstrap-token-file", bootstrap)
	identity, err := ReadManagedAccount(ctx)
	if err != nil {
		t.Fatal("installed account invalid")
	}
	identityJSON, _ := json.Marshal(identity)
	if os.WriteFile(filepath.Join(filepath.Dir(guardPath), "created-account.json"), identityJSON, 0600) != nil {
		t.Fatal("cleanup identity record failed")
	}
	certRoot := filepath.Join(base, "certificates", tlsFixtureID)
	if os.MkdirAll(filepath.Join(certRoot, "versions"), 0700) != nil {
		t.Fatal("certificate fixture failed")
	}
	addTLSVersion(t, certRoot, "one", time.Now().Add(time.Hour))
	if os.Symlink("versions/one", filepath.Join(certRoot, "current")) != nil {
		t.Fatal("certificate pointer failed")
	}
	coreRelease := model.CoreRelease{Type: "hysteria2", Version: PinnedVersion, SHA256: PinnedSHA256, DownloadURL: PinnedDownloadURL}
	installer, err := NewInstaller(base)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := installer.destination(coreRelease)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("/opt/vpn-platform-candidates/hysteria2-v0.1/hysteria-linux-amd64-v2.12.2")
	if err != nil || os.MkdirAll(filepath.Dir(destination), 0755) != nil || os.WriteFile(destination, source, 0555) != nil || os.Chmod(destination, 0555) != nil || installer.verify(ctx, destination) != nil {
		t.Fatal("core fixture pin failed")
	}
	port := nativePort(t)
	desired := model.DesiredState{Generation: 1, Core: coreRelease, Services: []model.ServiceSpec{{ID: "44444444-4444-4444-8444-444444444444", Protocol: "hysteria2", Listen: "127.0.0.1", Port: port, Transport: "udp", Security: "tls", TLS: &model.TLSSpec{CertificateID: tlsFixtureID, ServerName: "tls-probe.invalid"}, Clients: []model.ClientSpec{{ID: "55555555-5555-4555-8555-555555555555", StatsKey: "66666666-6666-4666-8666-666666666666"}}}}}
	start := time.Now()
	peer.assign(desired)
	nativeAwait(t, ctx, "initial leased deployment", func() bool { return peer.healthy(1, start) })
	stats, _, err := OpenStoredTrafficSource(base, ManagedService, false)
	if err != nil {
		t.Fatal(err)
	}
	system, _ := NewSystemdRuntime(ManagedService, stats)
	initial, err := system.Invocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("native-agent-payload", 4096)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, payload) }))
	defer origin.Close()
	startClient := func(name, credential string) *http.Client {
		socks := nativePort(t)
		config := map[string]any{"server": fmt.Sprintf("127.0.0.1:%d", port), "auth": credential, "tls": map[string]any{"sni": "tls-probe.invalid", "ca": filepath.Join(certRoot, "current", "fullchain.pem")}, "socks5": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", socks)}}
		raw, _ := json.Marshal(config)
		path := filepath.Join(fixture, name+".json")
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("client fixture failed")
		}
		cmd := exec.CommandContext(ctx, destination, "client", "-c", path)
		log, err := os.OpenFile(filepath.Join(fixture, name+".log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatal("private client log failed")
		}
		t.Cleanup(func() { _ = log.Close() })
		cmd.Stdout, cmd.Stderr = log, log
		if cmd.Start() != nil {
			t.Fatal("client process failed")
		}
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("client cleanup timeout")
			}
		})
		proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socks))
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
	revoked := desired.Services[0].Clients[0].ID
	if !reaches(startClient("initial", revoked)) {
		t.Fatal("real agent initial proxy failed")
	}
	desired.Generation = 2
	desired.Services[0].Clients = append(desired.Services[0].Clients, model.ClientSpec{ID: "77777777-7777-4777-8777-777777777777", StatsKey: "88888888-8888-4888-8888-888888888888"})
	start = time.Now()
	peer.assign(desired)
	nativeAwait(t, ctx, "access addition", func() bool { return peer.healthy(2, start) })
	if epoch, _ := system.Invocation(ctx); epoch != initial {
		t.Fatal("agent restarted core for access addition")
	}
	retained := desired.Services[0].Clients[1].ID
	if !reaches(startClient("retained", retained)) {
		t.Fatal("added client failed")
	}
	toolRun("repair")
	backupRaw, err := os.ReadFile(filepath.Join(base, "maintenance", "latest-backup"))
	if err != nil {
		t.Fatal("repair backup missing")
	}
	backup := strings.TrimSpace(string(backupRaw))
	desired.Generation = 3
	desired.Services[0].Clients = desired.Services[0].Clients[1:]
	start = time.Now()
	peer.assign(desired)
	nativeAwait(t, ctx, "revocation", func() bool { return peer.healthy(3, start) })
	if reaches(startClient("revoked", revoked)) {
		t.Fatal("revoked credential reconnected")
	}
	if !reaches(startClient("retained-after-revoke", retained)) {
		t.Fatal("retained credential failed")
	}
	beforeCrash, err := system.Invocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if exec.CommandContext(ctx, "systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", ManagedAgentService).Run() != nil {
		t.Fatal("actual agent crash injection failed")
	}
	nativeAwait(t, ctx, "actual agent crash recovery", func() bool {
		epoch, err := system.Invocation(ctx)
		return err == nil && epoch != beforeCrash && peer.healthy(3, start)
	})
	if !reaches(startClient("retained-after-crash", retained)) {
		t.Fatal("agent crash lost retained access")
	}
	nativeAwait(t, ctx, "crash final traffic delivery", func() bool { peer.mu.Lock(); defer peer.mu.Unlock(); return peer.epochs[beforeCrash] > 0 })
	toolRun("rollback", "--backup", backup)
	start = time.Now()
	nativeAwait(t, ctx, "compatible rollback", func() bool { return peer.healthy(3, start) })
	if reaches(startClient("revoked-after-rollback", revoked)) {
		t.Fatal("node-tool rollback restored revoked access")
	}
	if !reaches(startClient("retained-after-rollback", retained)) {
		t.Fatal("node-tool rollback lost retained access")
	}
	beforeUpgrade, _ := system.Invocation(ctx)
	toolRun("upgrade")
	if after, _ := system.Invocation(ctx); beforeUpgrade != after {
		t.Fatal("idempotent upgrade restarted runtime")
	}
	peer.mu.Lock()
	valid := !peer.bad && peer.registrations == 1 && peer.inspections == 1 && peer.claims >= 3 && peer.reports == 3 && peer.lastSequence > 0
	peer.mu.Unlock()
	if !valid {
		t.Fatal("native peer protocol invariants failed")
	}
	t.Log("actual pinned agent daemon: fresh install, leased apply, access addition without restart, repair backup, revocation, SIGKILL recovery with final traffic, compatible rollback preserving revocation, idempotent upgrade: PASS")
}
