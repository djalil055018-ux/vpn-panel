package hysteria

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

func revisionFixture(t *testing.T) (*revisionStore, model.DesiredState) {
	t.Helper()
	certificates, spec, _ := tlsFixture(t)
	resolved, err := certificates.Stage(spec)
	if err != nil {
		t.Fatal(err)
	}
	installer, err := NewInstaller(certificates.base)
	if err != nil {
		t.Fatal(err)
	}
	artifact := testELF(62)
	sum := sha256.Sum256(artifact)
	installer.pin = artifactPin{PinnedVersion, hex.EncodeToString(sum[:]), "https://test.invalid/reviewed-artifact", int64(len(artifact))}
	core := model.CoreRelease{Type: "hysteria2", Version: installer.pin.version, SHA256: installer.pin.sha256, DownloadURL: installer.pin.url}
	target, err := installer.destination(core)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(target, artifact, 0555) != nil || os.Chmod(target, 0555) != nil {
		t.Fatal("artifact fixture failed")
	}
	options := compiler.HysteriaRuntimeOptions{AuthPort: 12080, StatisticsPort: 12081, StatisticsSecret: strings.Repeat("s", 32)}
	store, err := newRevisionStore(installer, certificates, options)
	if err != nil {
		t.Fatal(err)
	}
	state := model.DesiredState{Generation: 1, Core: core, Services: []model.ServiceSpec{{ID: "33333333-3333-4333-8333-333333333333", Protocol: "hysteria2", Listen: "0.0.0.0", Port: 443, Transport: "udp", Security: "tls", TLS: &resolved, Clients: []model.ClientSpec{{ID: "55555555-5555-4555-8555-555555555555", StatsKey: "66666666-6666-4666-8666-666666666666"}}}}}
	return store, state
}
func TestRuntimeRevisionStagesWithoutActivationAndOmitsClientCredentials(t *testing.T) {
	store, state := revisionFixture(t)
	ctx := context.Background()
	first, err := store.stage(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if active, err := store.current(ctx); err != nil || active != nil {
		t.Fatal("staging activated revision")
	}
	for _, name := range []string{"metadata.json", "config.json"} {
		raw, err := os.ReadFile(filepath.Join(store.versions(), first.id, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(state.Services[0].Clients[0].ID)) || bytes.Contains(raw, []byte(state.Services[0].Clients[0].StatsKey)) {
			t.Fatal("runtime revision contains client credentials/identities")
		}
	}
	state.Generation++
	state.Services[0].Clients = nil
	state.Core.Channel = "new-registry-channel"
	same, err := store.stage(ctx, state)
	if err != nil || same.id != first.id {
		t.Fatal("access/generation/channel change requires restart")
	}
	if err = store.activate(ctx, first.id); err != nil {
		t.Fatal(err)
	}
	active, err := store.current(ctx)
	if err != nil || active.id != first.id || active.state.Generation != 0 || len(active.state.Services[0].Clients) != 0 {
		t.Fatal("active revision restore invalid")
	}
}
func TestRuntimeRevisionSwitchAndRollbackRetainsPreviousFiles(t *testing.T) {
	store, state := revisionFixture(t)
	ctx := context.Background()
	first, err := store.stage(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.activate(ctx, first.id); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(store.versions(), first.id, "config.json"))
	state.Services[0].Port = 444
	second, err := store.stage(ctx, state)
	if err != nil || second.id == first.id {
		t.Fatal("structural change lost")
	}
	if active, err := store.current(ctx); err != nil || active.id != first.id {
		t.Fatal("second stage changed live pointer")
	}
	if err = store.activate(ctx, second.id); err != nil {
		t.Fatal(err)
	}
	if err = store.restore(ctx, first); err != nil {
		t.Fatal(err)
	}
	active, err := store.current(ctx)
	if err != nil || active.id != first.id {
		t.Fatal("previous revision not restored")
	}
	retained, _ := os.ReadFile(filepath.Join(store.versions(), first.id, "config.json"))
	if !bytes.Equal(before, retained) {
		t.Fatal("previous revision modified")
	}
	if err = store.restore(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if active, err = store.current(ctx); err != nil || active != nil {
		t.Fatal("empty baseline not restored")
	}
	if _, err = os.Stat(filepath.Join(store.versions(), first.id, "metadata.json")); err != nil {
		t.Fatal("rollback deleted revision history")
	}
}
func TestRuntimeRevisionRejectsCorruptionWithoutChangingCurrent(t *testing.T) {
	for _, kind := range []string{"config", "metadata", "binary_link", "key"} {
		t.Run(kind, func(t *testing.T) {
			store, state := revisionFixture(t)
			ctx := context.Background()
			first, err := store.stage(ctx, state)
			if err != nil {
				t.Fatal(err)
			}
			if err = store.activate(ctx, first.id); err != nil {
				t.Fatal(err)
			}
			state.Services[0].Port = 444
			second, err := store.stage(ctx, state)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(store.versions(), second.id)
			switch kind {
			case "config":
				if err := os.WriteFile(filepath.Join(target, "config.json"), []byte(`{}`), 0640); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				if err := os.WriteFile(filepath.Join(target, "metadata.json"), []byte(`{}`), 0640); err != nil {
					t.Fatal(err)
				}
			case "binary_link":
				path := filepath.Join(target, "hysteria")
				if os.Remove(path) != nil || os.Symlink("/unreviewed/binary", path) != nil {
					t.Fatal("link fixture failed")
				}
			case "key":
				if err := os.Chmod(state.Services[0].TLS.KeyFile, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err = store.activate(ctx, second.id); err == nil {
				t.Fatal("corrupt revision activated")
			}
			link, err := os.Readlink(filepath.Join(store.root(), "current"))
			if err != nil || link != filepath.Join("revisions", first.id) {
				t.Fatal("failed activation changed current")
			}
		})
	}
}
func TestRuntimeRevisionIdleHasNoExecutableAndCanRollback(t *testing.T) {
	store, state := revisionFixture(t)
	ctx := context.Background()
	first, err := store.stage(ctx, state)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.activate(ctx, first.id); err != nil {
		t.Fatal(err)
	}
	state.Services = nil
	idle, err := store.stage(ctx, state)
	if err != nil || !idle.idle() {
		t.Fatal("idle stage failed", err)
	}
	if err = store.activate(ctx, idle.id); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hysteria", "config.json"} {
		if _, err = os.Lstat(filepath.Join(store.versions(), idle.id, name)); !os.IsNotExist(err) {
			t.Fatal("idle revision can launch a core")
		}
	}
	if err = store.restore(ctx, first); err != nil {
		t.Fatal(err)
	}
}
func TestRuntimeRevisionRejectsCancelledAndUnownedCurrentPaths(t *testing.T) {
	store, state := revisionFixture(t)
	first, err := store.stage(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if store.activate(ctx, first.id) == nil {
		t.Fatal("cancelled activation accepted")
	}
	path := filepath.Join(store.root(), "current")
	if os.WriteFile(path, []byte("unexpected file"), 0600) != nil {
		t.Fatal("fixture failed")
	}
	if store.activate(context.Background(), first.id) == nil || store.restore(context.Background(), nil) == nil {
		t.Fatal("unrecognized current file replaced")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "unexpected file" {
		t.Fatal("unexpected file changed")
	}
}
