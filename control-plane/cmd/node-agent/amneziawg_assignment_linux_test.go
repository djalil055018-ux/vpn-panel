//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/agent"
	"vpn-platform/internal/core"
	"vpn-platform/internal/core/wireguard"
	"vpn-platform/internal/model"
)

// This opt-in test uses the real native runtime and lease supervisor in an
// isolated network namespace. The HTTP fixture models Control Plane commits;
// database dialect/configuration ownership is verified separately.
func TestAmneziaWGNativeAgentAssignmentLifecycle(t *testing.T) {
	if os.Getenv("PAUK_AWG_AGENT_TEST") != "1" {
		t.Skip("owned isolated network namespace required")
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	initial, _ := os.Readlink("/proc/1/ns/net")
	if os.Geteuid() != 0 || ns == initial {
		t.Fatal("refusing host network namespace")
	}
	parent := os.Getenv("PAUK_AWG_AGENT_TEST_ROOT")
	source := os.Getenv("PAUK_AWG_ARTIFACT_ROOT")
	if !strings.HasPrefix(parent, "/root/pauk-full-audit-") || source == "" {
		t.Fatal("owned fixture required")
	}
	base, e := os.MkdirTemp(parent, "native-assignment-")
	if e != nil {
		t.Fatal("fixture directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	unlock, e := core.AcquireNodeOwnership(ctx, base)
	if e != nil {
		t.Fatal("ownership")
	}
	defer unlock()
	if _, e = core.SelectRuntimeCore(ctx, base, "amneziawg", agentVersion); e != nil {
		t.Fatal("selection")
	}
	dir := filepath.Join(base, "cores", "amneziawg", model.AmneziaWGNativeVersion)
	if e = os.MkdirAll(dir, 0700); e != nil {
		t.Fatal("artifact directories")
	}
	for _, name := range []string{"amneziawg-go", "awg"} {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal("fixture artifact")
		}
		if os.WriteFile(filepath.Join(dir, name), data, 0755) != nil {
			t.Fatal("fixture executable")
		}
	}
	if e = wireguard.ProvisionAmneziaWG(ctx, base); e != nil {
		t.Fatal("native provisioning")
	}
	statePath := filepath.Join(base, "agent", "state.json")
	local := agent.LocalState{NodeID: "33333333-3333-4333-8333-333333333333", TenantID: "44444444-4444-4444-8444-444444444444", AgentToken: "synthetic-agent-token"}
	if agent.SaveState(statePath, local) != nil {
		t.Fatal("fixture state")
	}
	key := func() string {
		var b [32]byte
		if _, e := rand.Read(b[:]); e != nil {
			t.Fatal("synthetic entropy")
		}
		return base64.StdEncoding.EncodeToString(b[:])
	}
	private, peerPrivate, psk := key(), key(), key()
	pub, e := model.WireGuardPublicKey(private)
	if e != nil {
		t.Fatal("synthetic identity")
	}
	peerPub, e := model.WireGuardPublicKey(peerPrivate)
	if e != nil {
		t.Fatal("synthetic peer")
	}
	var mu sync.Mutex
	desired := model.DesiredState{Core: model.CoreRelease{Type: "amneziawg", Version: model.AmneziaWGNativeVersion, DownloadURL: model.AmneziaWGDownloadURL, SHA256: model.AmneziaWGArtifactSHA256}}
	status := "pending"
	applied := int64(0)
	appliedVersion := ""
	reports := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-agent-token" {
			w.WriteHeader(401)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/agent/assignment":
			_ = json.NewEncoder(w).Encode(model.AgentAssignment{DesiredState: desired, DeploymentStatus: status, NodeAppliedGeneration: applied, AppliedCoreVersion: appliedVersion, Execution: model.ExecutionAssignment{DeploymentID: "11111111-1111-4111-8111-111111111111", Generation: desired.Generation, ExecutionID: "22222222-2222-4222-8222-222222222222", ExecutionEpoch: desired.Generation}})
		case "/api/v1/agent/execution/claim", "/api/v1/agent/execution/renew":
			_ = json.NewEncoder(w).Encode(integrationGrant())
		case "/api/v1/agent/deployment-status":
			var report model.DeploymentReport
			if json.NewDecoder(r.Body).Decode(&report) != nil {
				w.WriteHeader(400)
				return
			}
			if report.LeaseToken != "ram-only-lease-token" || report.ExecutionEpoch != desired.Generation {
				t.Error("invalid execution proof")
				w.WriteHeader(409)
				return
			}
			if report.Status == "healthy" {
				persisted, err := agent.LoadState(statePath)
				if err != nil || persisted.AppliedGeneration != applied {
					t.Error("agent advanced before terminal commit")
				}
				applied = desired.Generation
				appliedVersion = model.AmneziaWGNativeVersion
				reports++
			} else if report.Status != "applying" {
				t.Error("native assignment failed")
				w.WriteHeader(409)
				return
			}
			status = report.Status
			w.WriteHeader(204)
		case "/api/v1/agent/health", "/api/v1/agent/traffic":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client := agent.NewClient(server.URL)
	runtime, e := openAgentRuntime(ctx, "amneziawg", base, statePath, local, client)
	if e != nil {
		t.Fatal("factory could not open native AWG")
	}
	defer func() {
		if runtime != nil {
			if runtime.close() != nil {
				t.Error("runtime close")
			}
		}
	}()
	apply := func(t *testing.T) {
		t.Helper()
		var execution *leasedExecution
		if e := leaseSupervisorTick(ctx, client, runtime.driver, statePath, agent.SystemInfo{}, &local, "55555555-5555-4555-8555-555555555555", &execution); e != nil {
			t.Fatal("lease claim or start")
		}
		if execution == nil || execution.Worker == nil {
			t.Fatal("leased worker missing")
		}
		select {
		case result := <-execution.Worker.done:
			if result.Err != nil {
				t.Fatalf("real native assignment failed: %v", result.Err)
			}
			execution.Worker = nil
			execution.PendingResult = &result
		case <-ctx.Done():
			t.Fatal("real native assignment timed out")
		}
		if e := leaseSupervisorTick(ctx, client, runtime.driver, statePath, agent.SystemInfo{}, &local, "55555555-5555-4555-8555-555555555555", &execution); e != nil || execution != nil {
			t.Fatal("terminal commit")
		}
		healthy, err := runtime.driver.Health()
		if err != nil || !healthy {
			t.Fatal("native health")
		}
	}
	output := func(args ...string) string {
		t.Helper()
		raw, err := exec.CommandContext(ctx, filepath.Join(dir, "awg"), args...).Output()
		if err != nil {
			t.Fatal("native tool unavailable")
		}
		return strings.TrimSpace(string(raw))
	}
	for _, version := range []string{"1.0", "1.5", "2.0", "3.0", "3.1"} {
		t.Run(version, func(t *testing.T) {
			spec, err := model.NewAmneziaWGSpec(version)
			if err != nil {
				t.Fatal("dialect")
			}
			mu.Lock()
			desired.Generation++
			desired.Services = []model.ServiceSpec{{ID: "66666666-6666-4666-8666-666666666666", Protocol: "amneziawg", Listen: "0.0.0.0", Port: 51820, Transport: "udp", Security: "amneziawg", WireGuard: &model.WireGuardSpec{PrivateKey: private}, AmneziaWG: spec, Clients: []model.ClientSpec{{ID: "77777777-7777-4777-8777-777777777777", StatsKey: "77777777-7777-4777-8777-777777777777", WireGuard: &model.WireGuardPeer{PublicKey: peerPub, PresharedKey: psk, Address: "10.66.0.2/32"}}}}}
			status = "pending"
			generation := desired.Generation
			mu.Unlock()
			apply(t)
			if output("show", wireguard.InterfaceName, "public-key") != pub || output("show", wireguard.InterfaceName, "peers") != peerPub {
				t.Fatal("assignment lost native identities")
			}
			if local.AppliedGeneration != generation {
				t.Fatal("local generation not committed")
			}
		})
	}
	mu.Lock()
	desired.Generation++
	desired.Services[0].Clients = nil
	status = "pending"
	mu.Unlock()
	apply(t)
	if output("show", wireguard.InterfaceName, "peers") != "" {
		t.Fatal("revoked peer remains")
	}
	var process struct{ PID int }
	raw, err := os.ReadFile(filepath.Join(base, "amneziawg", "process.json"))
	if err != nil || json.Unmarshal(raw, &process) != nil || process.PID < 1 {
		t.Fatal("owned native process receipt missing")
	}
	ownedProcess, err := os.FindProcess(process.PID)
	if err != nil {
		t.Fatal("owned native process unavailable")
	}
	command, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(process.PID), "cmdline"))
	if err != nil || strings.Split(string(command), "\x00")[0] != filepath.Join(dir, "amneziawg-go") {
		ownedProcess.Release()
		t.Fatal("refusing to kill unrelated process")
	}
	if ownedProcess.Kill() != nil {
		ownedProcess.Release()
		t.Fatal("owned native crash injection failed")
	}
	ownedProcess.Release()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := net.InterfaceByName(wireguard.InterfaceName); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("crashed daemon retained native interface")
		}
		time.Sleep(25 * time.Millisecond)
	}
	control := "/var/run/amneziawg/" + wireguard.InterfaceName + ".sock"
	ownedSocket := control + ".owned-test"
	if os.Rename(control, ownedSocket) != nil {
		t.Fatal("owned stale socket missing")
	}
	foreign, err := net.Listen("unix", control)
	if err != nil {
		t.Fatal("replacement control socket fixture")
	}
	if runtime.close() == nil {
		foreign.Close()
		t.Fatal("foreign replacement socket accepted")
	}
	if _, err := os.Lstat(control); err != nil {
		foreign.Close()
		t.Fatal("foreign socket removed")
	}
	if foreign.Close() != nil || os.Rename(ownedSocket, control) != nil {
		t.Fatal("restore owned stale socket fixture")
	}
	if runtime.close() != nil {
		t.Fatal("native close before restart")
	}
	runtime = nil
	if _, err := os.Lstat("/var/run/amneziawg/" + wireguard.InterfaceName + ".sock"); !os.IsNotExist(err) {
		t.Fatal("stale native control socket after crash cleanup")
	}
	runtime, e = openAgentRuntime(ctx, "amneziawg", base, statePath, local, client)
	if e != nil {
		t.Fatal("native reopen")
	}
	var execution *leasedExecution
	if e = leaseSupervisorTick(ctx, client, runtime.driver, statePath, agent.SystemInfo{}, &local, "55555555-5555-4555-8555-555555555555", &execution); e != nil {
		t.Fatal("healthy committed assignment restore")
	}
	healthy, e := runtime.driver.Health()
	if e != nil || !healthy || output("show", wireguard.InterfaceName, "peers") != "" {
		t.Fatal("restart restored stale access or lost healthy assignment")
	}
	mu.Lock()
	count := reports
	mu.Unlock()
	if count != 6 {
		t.Fatal("wrong terminal commit count")
	}
}
