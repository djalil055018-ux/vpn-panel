//go:build linux

package xray

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpn-platform/internal/compiler"
	"vpn-platform/internal/core"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

const importedService = "11111111-1111-4111-8111-111111111111"
const importedCredential = "22222222-2222-4222-8222-222222222222"
const importedStats = "33333333-3333-4333-8333-333333333333"

func TestImportedTerminalRestorePersistsFloorBeforeServiceManager(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned runtime")
	}
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt-selection"}[invalid], func(t *testing.T) {
			state, _ := importedFixture(t, false)
			d, calls := profileDriver(t, state)
			if err := os.Symlink(state.Core.Version, d.currentLink()); err != nil {
				t.Fatal(err)
			}
			if invalid {
				if err := os.WriteFile(filepath.Join(d.BaseDir, "runtime-selection.json"), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			assignment := model.AgentAssignment{DeploymentStatus: "healthy", NodeAppliedGeneration: state.Generation, AppliedCoreVersion: state.Core.Version, DesiredState: state}
			err := d.RestoreTerminalAssignment(context.Background(), assignment)
			if invalid {
				if err == nil {
					t.Fatal("corrupt selection restored")
				}
				if _, e := os.Stat(calls); !os.IsNotExist(e) {
					t.Fatal("unsafe selection reached service manager")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := core.ReadRuntimeSelection(d.BaseDir, "xray", "0.2.30"); err == nil {
					t.Fatal("restored profile permits legacy Agent")
				}
				record, err := core.ReadRuntimeSelection(d.BaseDir, "xray", "0.2.31")
				if err != nil || record.MinimumAgent != "0.2.31" {
					t.Fatal("compatible restart", err)
				}
			}
		})
	}
}

func importedFixture(t *testing.T, tls bool) (model.DesiredState, string) {
	t.Helper()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	stream := map[string]any{"network": "grpc", "security": "reality",
		"grpcSettings":    map[string]any{"serviceName": "original-grpc", "multiMode": true},
		"realitySettings": map[string]any{"target": "example.org:443", "serverNames": []string{"example.org"}, "shortIds": []string{""}, "privateKey": key}}
	protocol := "vless"
	settings := map[string]any{"clients": []any{}, "decryption": "none"}
	service := model.ServiceSpec{ID: importedService, Protocol: "vless", Listen: "0.0.0.0", Port: 8443, Transport: "grpc", Security: "reality",
		Clients: []model.ClientSpec{{ID: importedCredential, StatsKey: importedStats}},
		Reality: &model.RealitySpec{Destination: "example.org:443", ServerName: "example.org", ShortID: "", SecretRef: "reality/" + importedService, PrivateKey: key}}
	if tls {
		protocol = "hysteria"
		settings = map[string]any{"clients": []any{}, "version": 2}
		stream = map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2}, "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": "/source/cert.pem", "keyFile": "/source/key.pem"}}}}
		service.Protocol, service.Transport, service.Security = "hysteria2", "udp", "tls"
		service.Reality = nil
		service.TLS = &model.TLSSpec{CertificateID: importedService, ServerName: "example.org", CertificateFile: "/runtime/cert.pem", KeyFile: "/runtime/key.pem"}
	}
	raw, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"tag": "original-tag", "listen": "0.0.0.0", "port": 8443, "protocol": protocol, "settings": settings, "streamSettings": stream}}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}})
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := xrayprofile.Project(raw, []model.XrayProfileBinding{{ServiceID: importedService, InboundTag: "original-tag"}})
	if err != nil {
		t.Fatal(err)
	}
	return model.DesiredState{Generation: 5, Core: model.CoreRelease{Type: "xray", Version: xrayprofile.MinimumCore}, Services: []model.ServiceSpec{service}, XrayProfile: profile}, key
}

// Every service-manager call is intercepted. No real service/user is touched.
func profileDriver(t *testing.T, state model.DesiredState) (*Driver, string) {
	t.Helper()
	d := New(t.TempDir())
	for _, dir := range []string{d.xrayDir(), d.coresDir(), d.snapshotDir(), d.realitySecretsDir()} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	config, err := compiler.CompileXray(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(d.configPath(), config, 0600); err != nil {
		t.Fatal(err)
	}
	intent, err := d.accessIntent(state)
	if err != nil {
		t.Fatal(err)
	}
	intent.ConfigSHA256 = configDigest(config)
	if err = d.writeAccessFence(intent); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("XRAY_TEST_CALLS", calls)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$XRAY_TEST_CALLS\"\nexit 0\n"
	if err = os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return d, calls
}

func fakeProfileCore(t *testing.T, d *Driver) {
	t.Helper()
	if err := os.MkdirAll(d.versionDir(xrayprofile.MinimumCore), 0700); err != nil {
		t.Fatal(err)
	}
	// Deliberately fails native -test, with no dependency on an installed Xray.
	if err := os.WriteFile(d.binary(xrayprofile.MinimumCore), []byte("#!/bin/sh\nexit 19\n"), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestImportedRevokeClosesAccessBeforePreflightFailures(t *testing.T) {
	for _, failure := range []string{"cancelled", "snapshot", "install", "missing-key", "wrong-key", "missing-certificate", "native-validation", "unsupported-core"} {
		for _, change := range []string{"remove-client", "disable-service", "rotate"} {
			// A removed listener no longer needs its key/certificate.
			if change == "disable-service" && (failure == "missing-key" || failure == "wrong-key" || failure == "missing-certificate") {
				continue
			}
			t.Run(failure+"/"+change, func(t *testing.T) {
				initial, key := importedFixture(t, failure == "missing-certificate")
				d, calls := profileDriver(t, initial)
				state := initial
				state.Generation++
				state.Services = append([]model.ServiceSpec(nil), initial.Services...)
				switch change {
				case "remove-client":
					state.Services[0].Clients = nil
				case "disable-service":
					state.Services = nil
				case "rotate":
					state.Services[0].Clients = []model.ClientSpec{{ID: "44444444-4444-4444-8444-444444444444", StatsKey: importedStats}}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				fakeProfileCore(t, d)
				switch failure {
				case "cancelled":
					cancel()
				case "snapshot":
					if err := os.Remove(d.snapshotDir()); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(d.snapshotDir(), []byte("obstruction"), 0600); err != nil {
						t.Fatal(err)
					}
				case "install":
					if err := os.Remove(d.binary(xrayprofile.MinimumCore)); err != nil {
						t.Fatal(err)
					}
				case "wrong-key":
					key = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
				case "unsupported-core":
					state.Core.Version = "26.7.28"
				}
				if failure == "wrong-key" || failure == "native-validation" {
					if err := os.WriteFile(filepath.Join(d.realitySecretsDir(), importedService+".key"), []byte(key), 0600); err != nil {
						t.Fatal(err)
					}
				}
				err := d.Reconcile(ctx, state)
				if err == nil {
					t.Fatal("injected failure accepted")
				}
				stage := map[string]string{"cancelled": "context canceled", "snapshot": "snapshot:", "install": "install:", "missing-key": "imported Reality key", "wrong-key": "public identity", "missing-certificate": "TLS certificate files", "native-validation": "imported Xray native validation failed", "unsupported-core": "invalid or unsupported imported Xray profile"}[failure]
				if !strings.Contains(err.Error(), stage) {
					t.Fatalf("failure did not reach expected stage %s: %v", failure, err)
				}
				if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), importedCredential) {
					t.Fatal("secret in diagnostic")
				}
				log, _ := os.ReadFile(calls)
				if !strings.Contains(string(log), "stop vpn-platform-xray.service") || strings.Contains(string(log), "start ") {
					t.Fatal("withdrawn access was left running or restarted")
				}
				reopened := New(d.BaseDir)
				fence, err := reopened.readAccessFence()
				if err != nil || !fence.Blocked || fence.Generation != state.Generation {
					t.Fatal("durable revocation missing")
				}
				if reopened.CheckAccessFence() == nil || reopened.StartContext(context.Background()) == nil {
					t.Fatal("revocation bypassed after restart")
				}
				if reopened.RollbackContext(context.Background(), "unused") == nil {
					t.Fatal("rollback reopened removed credentials")
				}
				if _, err = reopened.accessIntent(initial); err == nil {
					t.Fatal("older generation accepted after failed revocation")
				}
				if failure == "missing-key" {
					if _, err = os.Stat(filepath.Join(d.realitySecretsDir(), importedService+".key")); !os.IsNotExist(err) {
						t.Fatal("replacement Reality key generated")
					}
				}
			})
		}
	}
}

func TestImportedUnchangedAuthorizationFailureLeavesRuntimeAlone(t *testing.T) {
	state, _ := importedFixture(t, false)
	d, calls := profileDriver(t, state)
	fakeProfileCore(t, d)
	before, err := os.ReadFile(filepath.Join(d.xrayDir(), "access-fence.json"))
	if err != nil {
		t.Fatal(err)
	}
	state.Generation++
	if err = d.Reconcile(context.Background(), state); err == nil || !strings.Contains(err.Error(), "imported Reality key") {
		t.Fatal("missing imported key not rejected")
	}
	if _, err = os.Stat(calls); !os.IsNotExist(err) {
		t.Fatal("healthy runtime touched on staging failure")
	}
	after, _ := os.ReadFile(filepath.Join(d.xrayDir(), "access-fence.json"))
	if !bytes.Equal(before, after) || d.CheckAccessFence() != nil {
		t.Fatal("healthy access receipt changed")
	}
}

func TestImportedRealityNeverGeneratesOrAcceptsReplacementKey(t *testing.T) {
	state, key := importedFixture(t, false)
	d, calls := profileDriver(t, state)
	file := filepath.Join(d.realitySecretsDir(), importedService+".key")
	for _, variant := range []string{"absent", "invalid", "different", "readable", "symlink", "correct"} {
		t.Run(variant, func(t *testing.T) {
			os.Remove(file)
			value := key
			if variant == "invalid" {
				value = "invalid"
			}
			if variant == "different" {
				value = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
			}
			if variant != "absent" {
				if err := os.WriteFile(file, []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "readable" {
				if err := os.Chmod(file, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "symlink" {
				target := filepath.Join(d.BaseDir, "key")
				if err := os.Rename(file, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, file); err != nil {
					t.Fatal(err)
				}
			}
			materials, err := d.RealityPublicMaterials(state)
			resolved, _, resolveErr := d.resolveRealitySecrets(state)
			if variant != "correct" {
				if err == nil || resolveErr == nil {
					t.Fatal("missing or replacement key accepted")
				}
				if variant == "absent" {
					if _, err = os.Stat(file); !os.IsNotExist(err) {
						t.Fatal("key generated by health/material collection")
					}
				}
			} else {
				if err != nil || resolveErr != nil || len(materials) != 1 || materials[0].PublicKey != state.XrayProfile.Bindings[0].RealityPublicKey || resolved.Services[0].Reality.PrivateKey != key {
					t.Fatal("original key not preserved")
				}
			}
		})
	}
	if _, err := os.Stat(calls); !os.IsNotExist(err) {
		t.Fatal("key lookup affected runtime")
	}
}
