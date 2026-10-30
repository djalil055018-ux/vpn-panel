//go:build linux

package wireguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"vpn-platform/internal/model"
)

func awgDesired(t *testing.T, generation int64) model.DesiredState {
	t.Helper()
	s := desired(generation)
	s.Core = model.CoreRelease{Type: "amneziawg", Version: model.AmneziaWGNativeVersion, DownloadURL: model.AmneziaWGDownloadURL, SHA256: model.AmneziaWGArtifactSHA256}
	spec, e := model.NewAmneziaWGSpec("3.1")
	if e != nil {
		t.Fatal(e)
	}
	s.Services[0].Protocol = "amneziawg"
	s.Services[0].Security = "amneziawg"
	s.Services[0].AmneziaWG = spec
	return s
}

func TestAmneziaWGGenerationFenceAndRuntimeIsolation(t *testing.T) {
	ctx := context.Background()
	root := testRoot(t)
	runtime := &fakeRuntime{}
	variant := amneziaWGVariant("/var/lib/vpn-platform")
	e, err := openEngine(ctx, root, runtime, variant)
	if err != nil {
		t.Fatal(err)
	}
	state := awgDesired(t, 1)
	if err = e.Reconcile(ctx, state); err != nil || !runtime.running {
		t.Fatal("valid AmneziaWG generation failed")
	}
	if err = e.Reconcile(ctx, desired(2)); err == nil {
		t.Fatal("WireGuard assignment accepted by AmneziaWG runtime")
	}
	bad := state
	bad.Core.SHA256 = strings.Repeat("0", 64)
	if err = e.Reconcile(ctx, bad); err == nil {
		t.Fatal("unreviewed core accepted")
	}
	changed := state
	copySpec := *state.Services[0].AmneziaWG
	copySpec.Jc++
	changed.Services = append([]model.ServiceSpec(nil), state.Services...)
	changed.Services[0].AmneziaWG = &copySpec
	if err = e.Reconcile(ctx, changed); err == nil {
		t.Fatal("different config accepted at same generation")
	}
	state.Generation = 2
	runtime.failStart = true
	if err = e.Reconcile(ctx, state); err == nil || runtime.running {
		t.Fatal("startup failure left access enabled")
	}
	runtime.failStart = false
	e, err = openEngine(ctx, root, runtime, variant)
	if err != nil {
		t.Fatal(err)
	}
	state.Generation = 1
	if err = e.Reconcile(ctx, state); err == nil || runtime.running {
		t.Fatal("restart lost generation high-water mark")
	}
	d := &Driver{engine: e, variant: variant}
	if d.CoreType() != "amneziawg" || d.runtimeVersion() != model.AmneziaWGNativeVersion {
		t.Fatal("wrong runtime identity")
	}
}

func TestAmneziaWGParameterChangeRequiresInterfaceReplacement(t *testing.T) {
	s := awgDesired(t, 1).Services[0]
	before := variantDigest(s)
	other := s
	other.Clients = append(other.Clients, model.ClientSpec{})
	if variantDigest(other) != before {
		t.Fatal("membership-only change changed parameter digest")
	}
	spec := *s.AmneziaWG
	spec.Jc++
	other.AmneziaWG = &spec
	if variantDigest(other) == before {
		t.Fatal("parameter change was not detected")
	}
	plain := desired(1).Services[0]
	if variantDigest(plain) != "" {
		t.Fatal("existing WireGuard receipt compatibility broken")
	}
}

func TestUserspaceStopDoesNotSignalUnrelatedProcess(t *testing.T) {
	root := testRoot(t)
	path := "/usr/bin/sleep"
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Skip("sleep unavailable")
	}
	sum := sha256.Sum256(raw)
	cmd := exec.Command(path, "30")
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	start, e := processStart(cmd.Process.Pid)
	if e != nil {
		t.Fatal(e)
	}
	r := interfaceReceipt{Epoch: strings.Repeat("a", 32)}
	data, e := json.Marshal(userspaceReceipt{Format: 1, PID: cmd.Process.Pid, Start: start, Epoch: r.Epoch})
	if e != nil {
		t.Fatal(e)
	}
	if e = writePrivate(filepath.Join(root, "process.json"), data); e != nil {
		t.Fatal(e)
	}
	k := &KernelRuntime{root: root, variant: &runtimeVariant{binaryPath: path, binarySHA: hex.EncodeToString(sum[:])}}
	if e = k.stopUserspace(context.Background(), r); e == nil {
		t.Fatal("unrelated command accepted as managed daemon")
	}
	if cmd.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("unrelated process was signaled")
	}
}
