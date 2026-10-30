//go:build linux

package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"vpn-platform/internal/compiler"
	"vpn-platform/internal/core"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

const runtimeCascadeID = "44444444-4444-4444-8444-444444444444"
const runtimeTransitID = "55555555-5555-4555-8555-555555555555"

func cascadeRuntimeFixture(t *testing.T, imported, exit bool) model.DesiredState {
	t.Helper()
	s, key := importedFixture(t, false)
	s.XrayProfile = nil
	s.Services[0].Transport = "tcp"
	s.Services[0].Reality.ShortID = "abcd"
	if imported {
		doc := map[string]any{"inbounds": []any{map[string]any{"tag": "original-tag", "listen": "0.0.0.0", "port": 8443, "protocol": "vless", "settings": map[string]any{"clients": []any{}, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"dest": "example.org:443", "serverNames": []string{"example.org"}, "shortIds": []string{"abcd"}, "privateKey": key}}}}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}}
		raw, _ := json.Marshal(doc)
		profile, _, err := xrayprofile.Project(raw, []model.XrayProfileBinding{{ServiceID: importedService, InboundTag: "original-tag"}})
		if err != nil {
			t.Fatal(err)
		}
		s.XrayProfile = profile
	}
	s.XrayCascades = &model.XrayCascadesSpec{Version: 1}
	if exit {
		s.XrayCascades.Exits = []model.XrayCascadeExit{{ID: runtimeCascadeID, ServiceID: importedService, ClientID: runtimeTransitID}}
	} else {
		s.XrayCascades.Entries = []model.XrayCascadeEntry{{ID: runtimeCascadeID, ServiceID: importedService, Port: 9443, Clients: append([]model.ClientSpec{}, s.Services[0].Clients...), Exit: model.XrayCascadeEndpoint{Address: "exit.example.org", Port: 443, ClientID: runtimeTransitID, ServerName: "example.org", PublicKey: key, ShortID: "abcd", Fingerprint: "firefox"}}}
	}
	return s
}

func TestCascadeAuthorizationMatchesNativeConfigWithoutLocalSecrets(t *testing.T) {
	for _, imported := range []bool{false, true} {
		for _, exit := range []bool{false, true} {
			s := cascadeRuntimeFixture(t, imported, exit)
			raw, err := compiler.CompileXray(s)
			if err != nil {
				t.Fatal(err)
			}
			s.Services[0].Reality.PrivateKey = ""
			auth, err := compiler.XrayAuthorizationConfig(s)
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := authorizationSet(raw)
			if err != nil {
				t.Fatal(err)
			}
			projected, err := authorizationSet(auth)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(compiled, projected) {
				t.Fatal("authorization differs from real compiler")
			}
			for _, field := range []string{"privateKey", "publicKey", "realitySettings", "streamSettings", "outbounds", "exit.example.org"} {
				if bytes.Contains(auth, []byte(field)) {
					t.Fatal("authorization contains server transport material")
				}
			}
		}
	}
}

func TestCascadeRevokeClosesAccessBeforeStagingFailure(t *testing.T) {
	for _, imported := range []bool{false, true} {
		for _, change := range []string{"remove-entry", "remove-entry-client", "remove-exit", "rotate-transit", "malformed-next"} {
			for _, failure := range []string{"cancelled", "snapshot", "install", "native-validation"} {
				name := map[bool]string{false: "native", true: "imported"}[imported] + "/" + change + "/" + failure
				t.Run(name, func(t *testing.T) {
					initial := cascadeRuntimeFixture(t, imported, change == "remove-exit" || change == "rotate-transit")
					d, calls := profileDriver(t, initial)
					state := initial
					state.Generation++
					switch change {
					case "remove-entry", "remove-exit":
						state.XrayCascades = nil
					case "remove-entry-client":
						state.XrayCascades.Entries[0].Clients = nil
					case "rotate-transit":
						state.XrayCascades.Exits[0].ClientID = "66666666-6666-4666-8666-666666666666"
					case "malformed-next":
						state.XrayCascades.Version = 2
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					fakeProfileCore(t, d)
					switch failure {
					case "cancelled":
						cancel()
					case "snapshot":
						if os.Remove(d.snapshotDir()) != nil || os.WriteFile(d.snapshotDir(), []byte("obstruction"), 0600) != nil {
							t.Fatal("fixture")
						}
					case "install":
						if err := os.Remove(d.binary(xrayprofile.MinimumCore)); err != nil {
							t.Fatal(err)
						}
					case "native-validation":
						if err := os.WriteFile(filepath.Join(d.realitySecretsDir(), importedService+".key"), []byte(state.Services[0].Reality.PrivateKey), 0600); err != nil {
							t.Fatal(err)
						}
					}
					err := d.Reconcile(ctx, state)
					if err == nil {
						t.Fatal("injected failure accepted")
					}
					if change != "malformed-next" {
						stage := map[string]string{"cancelled": "context canceled", "snapshot": "snapshot:", "install": "install:", "native-validation": "validation failed"}[failure]
						if !strings.Contains(err.Error(), stage) {
							t.Fatalf("wrong failure stage %s: %v", failure, err)
						}
					}
					log, _ := os.ReadFile(calls)
					if !strings.Contains(string(log), "stop vpn-platform-xray.service") || strings.Contains(string(log), "start ") {
						t.Fatal("revoked cascade kept running or reopened")
					}
					reopened := New(d.BaseDir)
					fence, e := reopened.readAccessFence()
					if e != nil || !fence.Blocked || fence.Generation != state.Generation {
						t.Fatal("durable revocation absent")
					}
					if reopened.StartContext(context.Background()) == nil || reopened.RollbackContext(context.Background(), "unused") == nil {
						t.Fatal("restart reopened credentials")
					}
					if strings.Contains(err.Error(), runtimeTransitID) || strings.Contains(err.Error(), importedCredential) {
						t.Fatal("secret diagnostic")
					}
				})
			}
		}
	}
}

func TestCascadeUnchangedAuthorizationDoesNotStopOnStagingFailure(t *testing.T) {
	for _, imported := range []bool{false, true} {
		for _, exit := range []bool{false, true} {
			s := cascadeRuntimeFixture(t, imported, exit)
			d, calls := profileDriver(t, s)
			s.Generation++
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if d.Reconcile(ctx, s) == nil {
				t.Fatal("cancelled operation accepted")
			}
			if _, err := os.Stat(calls); !os.IsNotExist(err) {
				t.Fatal("healthy runtime touched")
			}
			if d.CheckAccessFence() != nil {
				t.Fatal("healthy receipt changed")
			}
		}
	}
}

func TestCascadeTerminalRestoreRequiresNewAgentFloor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned runtime required")
	}
	for _, imported := range []bool{false, true} {
		for _, exit := range []bool{false, true} {
			s := cascadeRuntimeFixture(t, imported, exit)
			d, _ := profileDriver(t, s)
			if err := os.Symlink(s.Core.Version, d.currentLink()); err != nil {
				t.Fatal(err)
			}
			a := model.AgentAssignment{DeploymentStatus: "healthy", NodeAppliedGeneration: s.Generation, AppliedCoreVersion: s.Core.Version, DesiredState: s}
			if err := d.RestoreTerminalAssignment(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			if _, err := core.ReadRuntimeSelection(d.BaseDir, "xray", "0.2.33"); err == nil {
				t.Fatal("legacy agent accepted cascade runtime")
			}
			if chosen, err := core.ReadRuntimeSelection(d.BaseDir, "xray", "0.2.34"); err != nil || chosen.MinimumAgent != "0.2.34" {
				t.Fatal("new runtime floor absent", err)
			}
		}
	}
}
