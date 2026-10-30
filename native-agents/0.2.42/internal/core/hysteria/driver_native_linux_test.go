//go:build linux

package hysteria

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

type nativeFailureCore struct {
	*SystemdRuntime
	failNext bool
}

func (c *nativeFailureCore) Start(ctx context.Context) error {
	if c.failNext {
		c.failNext = false
		return ErrAccessRuntime
	}
	return c.SystemdRuntime.Start(ctx)
}
func nativePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("port reservation failed")
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Explicit opt-in only. All material, listeners, clients and the transient unit
// are isolated from platform production. RuntimeMaxSec also bounds an orphaned
// server if the test process is killed before its cleanup callbacks run.
func TestNativeDriverSystemdRenewalRevocationRollback(t *testing.T) {
	if os.Getenv("HYSTERIA_NATIVE_DRIVER") != "1" {
		t.Skip("isolated native driver proof requires explicit opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native driver proof requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	base, err := os.MkdirTemp("/opt", "vpn-hysteria-driver-")
	if err != nil {
		t.Fatal("fixture allocation failed")
	}
	defer os.RemoveAll(base)
	if os.Chmod(base, 0755) != nil {
		t.Fatal("fixture permissions failed")
	}
	helperPath := filepath.Join(base, "node-agent-stop-helper")
	helper, err := os.ReadFile("/opt/vpn-platform-candidates/hysteria2-v0.1/node-agent-stop-helper")
	if err != nil || os.WriteFile(helperPath, helper, 0555) != nil {
		t.Fatal("compiled stop helper fixture missing")
	}
	if os.Mkdir(filepath.Join(base, "agent"), 0700) != nil || os.WriteFile(filepath.Join(base, "agent", "state.json"), []byte(`{"node_id":"99999999-9999-4999-8999-999999999999"}`), 0600) != nil {
		t.Fatal("private stop capture fixture failed")
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal("fixture account missing")
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	certRoot := filepath.Join(base, "certificates", tlsFixtureID)
	if os.MkdirAll(filepath.Join(certRoot, "versions"), 0700) != nil {
		t.Fatal("certificate fixture failed")
	}
	addTLSVersion(t, certRoot, "one", time.Now().Add(time.Hour))
	if os.Symlink("versions/one", filepath.Join(certRoot, "current")) != nil {
		t.Fatal("certificate pointer failed")
	}
	certs, err := NewCertificateRuntime(base, gid)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := NewInstaller(base)
	if err != nil {
		t.Fatal(err)
	}
	core := model.CoreRelease{Type: "hysteria2", Version: PinnedVersion, SHA256: PinnedSHA256, DownloadURL: PinnedDownloadURL}
	destination, err := installer.destination(core)
	if err != nil {
		t.Fatal(err)
	}
	if os.MkdirAll(filepath.Dir(destination), 0755) != nil {
		t.Fatal("artifact directory failed")
	}
	source, err := os.ReadFile("/opt/vpn-platform-candidates/hysteria2-v0.1/hysteria-linux-amd64-v2.12.2")
	if err != nil {
		t.Fatal("verified probe artifact missing")
	}
	if os.WriteFile(destination, source, 0555) != nil || os.Chmod(destination, 0555) != nil || installer.verify(ctx, destination) != nil {
		t.Fatal("artifact verification failed")
	}
	entropy := make([]byte, 32)
	if _, err = rand.Read(entropy); err != nil {
		t.Fatal("fixture random failed")
	}
	settings, err := openRuntimeSettings(base, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	options := settings.options()
	store, err := newRevisionStore(installer, certs, options)
	if err != nil {
		t.Fatal(err)
	}
	// An idle revision creates the protected runtime directories without activation.
	if _, err = store.stage(ctx, model.DesiredState{Core: core}); err != nil {
		t.Fatal(err)
	}
	unit := "vpn-platform-hysteria-candidate-" + hex.EncodeToString(entropy[:8]) + ".service"
	unitPath := filepath.Join("/run/systemd/system", unit)
	owner := "vpn-platform-node-agent-candidate-" + hex.EncodeToString(entropy[:8]) + ".service"
	ownerPath := filepath.Join("/run/systemd/system", owner)
	ownerFile, err := os.OpenFile(ownerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal("owner fixture allocation failed")
	}
	_, ownerWrite := ownerFile.WriteString("[Service]\nType=simple\nExecStart=/usr/bin/sleep 150\nRestart=no\nRuntimeMaxSec=180\nStandardOutput=null\nStandardError=null\n")
	ownerClose := ownerFile.Close()
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanup, "systemctl", "stop", owner).Run()
		if os.Remove(ownerPath) != nil {
			t.Error("owner fixture cleanup failed")
		}
		_ = exec.CommandContext(cleanup, "systemctl", "reset-failed", owner).Run()
		if exec.CommandContext(cleanup, "systemctl", "daemon-reload").Run() != nil {
			t.Error("owner fixture reload failed")
		}
	}()
	if ownerWrite != nil || ownerClose != nil {
		t.Fatal("owner fixture write failed")
	}
	if _, err := os.Lstat(unitPath); !os.IsNotExist(err) {
		t.Fatal("candidate unit path already exists")
	}
	provisioner := unitProvisioner{directory: "/run/systemd/system", unit: unit, owner: owner, agentBinary: helperPath, run: func(ctx context.Context, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "systemctl", args...).Output()
	}}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if _, exists := os.Lstat(unitPath); os.IsNotExist(exists) {
			return
		}
		if exec.CommandContext(cleanup, "systemctl", "stop", unit).Run() != nil {
			t.Error("native unit cleanup stop failed")
		}
		if os.Remove(unitPath) != nil {
			t.Error("native unit cleanup file failed")
		}
		if exec.CommandContext(cleanup, "systemctl", "daemon-reload").Run() != nil {
			t.Error("native unit cleanup reload failed")
		}
	}()
	if err = provisioner.ensure(ctx, base, ManagedIdentity{uid, gid}); err != nil {
		t.Fatal("unit fixture load failed")
	}
	stats, err := NewStatistics(options.StatisticsPort, options.StatisticsSecret)
	if err != nil {
		t.Fatal(err)
	}
	system, err := NewSystemdRuntime(unit, stats)
	if err != nil {
		t.Fatal(err)
	}
	if err = system.Stopped(ctx); err != nil {
		t.Fatal("unit provisioning unexpectedly started core")
	}
	runtime := &nativeFailureCore{SystemdRuntime: system}
	control := filepath.Join(store.root(), "control")
	if err := os.Mkdir(control, 0700); err != nil && !os.IsExist(err) {
		t.Fatal("private checkpoint directory failed")
	}
	tx, err := newRuntimeTransaction(store, runtime, filepath.Join(control, "access.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := StartAuthorizationServer(options.AuthPort, tx.access)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if auth.Close() != nil {
			t.Error("authorization cleanup failed")
		}
	}()
	driver, err := newDriver(tx, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	port := nativePort(t)
	for port == options.AuthPort || port == options.StatisticsPort {
		port = nativePort(t)
	}
	state := model.DesiredState{Generation: 1, Core: core, Services: []model.ServiceSpec{{ID: "33333333-3333-4333-8333-333333333333", Protocol: "hysteria2", Listen: "127.0.0.1", Port: port, Transport: "udp", Security: "tls", TLS: &model.TLSSpec{CertificateID: tlsFixtureID, ServerName: "tls-probe.invalid"}, Clients: []model.ClientSpec{{ID: "55555555-5555-4555-8555-555555555555", StatsKey: "66666666-6666-4666-8666-666666666666"}}}}}
	if err = driver.Reconcile(ctx, state); err != nil {
		t.Fatal("initial native reconcile failed", err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "native-driver-proof") }))
	defer origin.Close()
	startClient := func(name, credential string) *http.Client {
		socks := nativePort(t)
		config := map[string]any{"server": fmt.Sprintf("127.0.0.1:%d", port), "auth": credential, "tls": map[string]any{"sni": "tls-probe.invalid", "ca": filepath.Join(certRoot, "current", "fullchain.pem")}, "socks5": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", socks)}}
		raw, encodeErr := json.Marshal(config)
		if encodeErr != nil {
			t.Fatal("client fixture encoding failed")
		}
		path := filepath.Join(base, name+".json")
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("client fixture write failed")
		}
		command := exec.CommandContext(ctx, destination, "client", "-c", path)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if command.Start() != nil {
			t.Fatal("native client start failed")
		}
		done := make(chan struct{})
		go func() { _ = command.Wait(); close(done) }()
		t.Cleanup(func() {
			_ = command.Process.Kill()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("native client cleanup failed")
			}
		})
		proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socks))
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: time.Second}
	}
	reaches := func(client *http.Client) bool {
		for attempt := 0; attempt < 8; attempt++ {
			response, requestErr := client.Get(origin.URL)
			if requestErr == nil {
				body, _ := io.ReadAll(io.LimitReader(response.Body, 128))
				response.Body.Close()
				if string(body) == "native-driver-proof" {
					return true
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		return false
	}
	firstClient := startClient("first", state.Services[0].Clients[0].ID)
	if !reaches(firstClient) {
		t.Fatal("initial native proxy failed")
	}
	initialInvocation, err := system.Invocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.Generation = 2
	state.Services[0].Clients = append(state.Services[0].Clients, model.ClientSpec{ID: "77777777-7777-4777-8777-777777777777", StatsKey: "88888888-8888-4888-8888-888888888888"})
	if err = driver.Reconcile(ctx, state); err != nil {
		t.Fatal(err)
	}
	invocation, _ := system.Invocation(ctx)
	if invocation != initialInvocation {
		t.Fatal("native addition restarted core")
	}
	retainedClient := startClient("retained", state.Services[0].Clients[1].ID)
	if !reaches(retainedClient) {
		t.Fatal("added native credential failed")
	}
	if err := driver.ConfirmHealthyDesired(ctx, state); err != nil {
		t.Fatal("native confirmed receipt failed", err)
	}
	previous, err := store.current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	removedCredential := state.Services[0].Clients[0].ID
	state.Generation = 3
	state.Services[0].Clients = state.Services[0].Clients[1:]
	state.Services[0].Port = nativePort(t)
	runtime.failNext = true
	if err = driver.Reconcile(ctx, state); err == nil {
		t.Fatal("injected native startup failure accepted")
	}
	recovered, err := store.current(ctx)
	if err != nil || recovered.id != previous.id {
		t.Fatal("native rollback did not restore config")
	}
	if reaches(firstClient) {
		t.Fatal("revoked native connection survived rollback")
	}
	if reaches(startClient("revoked-reconnect", removedCredential)) {
		t.Fatal("revoked native credential reconnected after rollback")
	}
	// The native CLI exits on lost sessions; retained users reconnect with the
	// same credential after a deliberate full-invocation revocation.
	if !reaches(startClient("retained-reconnect", state.Services[0].Clients[0].ID)) {
		t.Fatal("retained native client failed to reconnect after rollback")
	}
	addTLSVersion(t, certRoot, "renewed", time.Now().Add(2*time.Hour))
	if rotateTLSVersion(certRoot, "renewed") != nil {
		t.Fatal("renewal fixture failed")
	}
	beforeRenewal, _ := system.Invocation(ctx)
	if err = driver.RefreshTLSCertificateContext(ctx, tlsFixtureID, "tls-probe.invalid"); err != nil {
		t.Fatal("native certificate renewal failed", err)
	}
	afterRenewal, _ := system.Invocation(ctx)
	if afterRenewal == beforeRenewal {
		t.Fatal("renewal reused old invocation")
	}
	renewedClient := startClient("renewed", state.Services[0].Clients[0].ID)
	if !reaches(renewedClient) {
		t.Fatal("renewed certificate proxy failed")
	}
	generation, _ := tx.access.policy.PendingRevocations()
	if generation != 3 {
		t.Fatal("native renewal rewound access generation")
	}
	if healthy, err := driver.Health(); !healthy || err != nil {
		t.Fatal("native driver unhealthy")
	}
	if driver.CurrentVersion() != PinnedVersion {
		t.Fatal("invalid core version")
	}
	cancelled, stopCancelled := context.WithCancel(ctx)
	stopCancelled()
	beforeCancelled, _ := system.Invocation(ctx)
	if _, err := OpenManagedDriver(cancelled, base, uid, gid, unit, nil); err == nil {
		t.Fatal("cancelled driver open succeeded")
	}
	afterCancelled, _ := system.Invocation(ctx)
	if beforeCancelled != afterCancelled {
		t.Fatal("cancelled driver open disturbed current runtime")
	}
	if err := auth.Close(); err != nil {
		t.Fatal("old lifetime close failed")
	}
	restoredDriver, err := OpenPendingManagedDriver(ctx, base, uid, gid, unit, nil)
	if err != nil {
		t.Fatal("driver lifetime reconstruction failed", err)
	}
	if system.Stopped(ctx) != nil {
		t.Fatal("rollback lifetime started before authority")
	}
	rollbackAssignment := model.AgentAssignment{DeploymentStatus: "rolled_back", NodeAppliedGeneration: 2, AppliedCoreVersion: PinnedVersion, DesiredState: state}
	unprovenRollback := rollbackAssignment
	unprovenRollback.NodeAppliedGeneration = 1
	if restoredDriver.RestoreRolledBackAssignment(ctx, unprovenRollback) == nil || system.Stopped(ctx) != nil {
		t.Fatal("unproven rollback restored core")
	}
	if err := restoredDriver.RestoreRolledBackAssignment(ctx, rollbackAssignment); err != nil {
		t.Fatal("confirmed rollback lifetime restoration failed", err)
	}
	defer func() {
		if err := restoredDriver.Close(); err != nil {
			t.Error("restored driver close failed")
		}
	}()
	if !reaches(startClient("restored-retained", state.Services[0].Clients[0].ID)) {
		t.Fatal("restored lifetime lost retained access")
	}
	if reaches(startClient("restored-revoked", removedCredential)) {
		t.Fatal("restored lifetime regranted revoked access")
	}
	if healthy, err := restoredDriver.Health(); err != nil || !healthy || restoredDriver.Statistics() == nil {
		t.Fatal("restored lifetime unhealthy")
	}
	if epoch, err := restoredDriver.Invocation(ctx); err != nil || epoch == afterRenewal {
		t.Fatal("restored lifetime reused old invocation")
	}
	// Confirm a new healthy generation on the restored configuration, then prove
	// normal startup remains stopped until that exact healthy intent is supplied.
	state.Generation = 4
	state.Services[0].Port = previous.state.Services[0].Port
	if err = restoredDriver.Reconcile(ctx, state); err != nil {
		t.Fatal("healthy terminal fixture failed", err)
	}
	if err = restoredDriver.Close(); err != nil {
		t.Fatal("terminal fixture close failed")
	}
	pendingDriver, err := OpenPendingManagedDriver(ctx, base, uid, gid, unit, nil)
	if err != nil {
		t.Fatal("pending lifetime open failed", err)
	}
	defer pendingDriver.Close()
	if system.Stopped(ctx) != nil {
		t.Fatal("pending startup launched an unconfirmed core")
	}
	unconfirmed := state
	unconfirmed.Generation++
	if pendingDriver.RestoreHealthyDesired(ctx, unconfirmed) == nil || system.Stopped(ctx) != nil {
		t.Fatal("unconfirmed generation started core")
	}
	if err = pendingDriver.RestoreHealthyDesired(ctx, state); err != nil {
		t.Fatal("confirmed terminal restore failed", err)
	}
	if !reaches(startClient("terminal-restored-retained", state.Services[0].Clients[0].ID)) {
		t.Fatal("terminal recovery proxy failed")
	}
	restoredDriver = pendingDriver
	finalEpoch, err := system.Invocation(ctx)
	if err != nil {
		t.Fatal("pre-crash epoch missing")
	}
	finalCounts, err := stats.Traffic(ctx)
	if err != nil || len(finalCounts) == 0 {
		t.Fatal("pre-crash traffic missing")
	}
	if exec.CommandContext(ctx, "systemctl", "kill", "--signal=SIGKILL", owner).Run() != nil {
		t.Fatal("owner crash injection failed")
	}
	stopped := false
	for attempt := 0; attempt < 50; attempt++ {
		if system.Stopped(ctx) == nil {
			stopped = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !stopped {
		t.Fatal("managed core survived loss of its owner service")
	}
	// Read the helper's durable, checksummed records without importing agent
	// (agent depends on this package). No API server or agent process is alive.
	records, err := filepath.Glob(filepath.Join(base, "agent", "traffic-outbox", "*.json"))
	if err != nil {
		t.Fatal("stop capture listing failed")
	}
	captured := false
	for _, path := range records {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("stop capture read failed")
		}
		var envelope struct {
			Data   json.RawMessage `json:"data"`
			SHA256 string          `json:"sha256"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			t.Fatal("stop capture envelope malformed")
		}
		sum := sha256.Sum256(envelope.Data)
		if hex.EncodeToString(sum[:]) != envelope.SHA256 {
			t.Fatal("stop capture checksum failed")
		}
		var delivery model.TrafficDelivery
		if json.Unmarshal(envelope.Data, &delivery) != nil {
			t.Fatal("stop capture payload malformed")
		}
		if delivery.Snapshot.Epoch != finalEpoch {
			continue
		}
		found := map[string]model.ClientTraffic{}
		for _, client := range delivery.Snapshot.Clients {
			found[client.ClientID] = client
		}
		for id, count := range finalCounts {
			client, exists := found[id]
			if !exists || uint64(client.Uplink) < count.UploadBytes || uint64(client.Downlink) < count.DownloadBytes {
				t.Fatal("final invocation counters were lost")
			}
		}
		captured = true
	}
	if !captured {
		t.Fatal("owner crash did not durably capture final invocation")
	}
	if err = restoredDriver.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err = restoredDriver.Recover(ctx); err == nil {
		t.Fatal("closed restored lifetime recovered")
	}
	if err = system.Stopped(ctx); err != nil {
		t.Fatal("native shutdown did not stop unit")
	}
	t.Log("native driver: real proxy, additions without restart, revoke+startup-failure rollback, TLS renewal, full lifetime reopen preserves policy, owner-service crash stop with durable final traffic capture, permanent shutdown: PASS")
}
