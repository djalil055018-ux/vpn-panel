//go:build linux

package wireguard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

type runtimeVariant struct {
	coreType, version, downloadURL, artifactSHA string
	binaryPath, binarySHA, toolPath, toolSHA    string
}

func amneziaWGVariant(base string) *runtimeVariant {
	root := filepath.Join(base, "cores", "amneziawg", model.AmneziaWGNativeVersion)
	return &runtimeVariant{coreType: "amneziawg", version: model.AmneziaWGNativeVersion, downloadURL: model.AmneziaWGDownloadURL, artifactSHA: model.AmneziaWGArtifactSHA256, binaryPath: filepath.Join(root, "amneziawg-go"), binarySHA: model.AmneziaWGDaemonSHA256, toolPath: filepath.Join(root, "awg"), toolSHA: model.AmneziaWGToolSHA256}
}

func checkedExecutable(path, expected string) error {
	// Binaries are addressed by immutable version, not by a mutable current link.
	for p := filepath.Dir(path); p != "/"; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return ErrRuntime
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return ErrRuntime
		}
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return ErrRuntime
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0100 == 0 || info.Size() > 64<<20 {
		return ErrRuntime
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return ErrRuntime
	}
	data, e := io.ReadAll(io.LimitReader(f, 64<<20+1))
	if e != nil {
		return ErrRuntime
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expected {
		return ErrRuntime
	}
	return nil
}

func (v *runtimeVariant) verify() error {
	for path, want := range map[string]string{v.binaryPath: v.binarySHA, v.toolPath: v.toolSHA, "/usr/sbin/nft": model.WireGuardNFTSHA256} {
		if e := checkedExecutable(path, want); e != nil {
			return e
		}
	}
	return nil
}
func (v *runtimeVariant) validate(state model.DesiredState) error {
	if state.Core.Type != v.coreType || state.Core.Version != v.version || state.Core.DownloadURL != v.downloadURL || state.Core.SHA256 != v.artifactSHA {
		return ErrRuntime
	}
	return nil
}
func (d *Driver) validateState(state model.DesiredState) error {
	if d.variant != nil {
		return d.variant.validate(state)
	}
	return nativeState(state)
}
func (d *Driver) verifyTools() error {
	if d.variant != nil {
		return d.variant.verify()
	}
	return verifyTools()
}
func (d *Driver) runtimeVersion() string {
	if d.variant != nil {
		return d.variant.version
	}
	return model.WireGuardNativeVersion
}
func (k *KernelRuntime) tool() string {
	if k.variant != nil {
		return k.variant.toolPath
	}
	return "/usr/bin/wg"
}
func (k *KernelRuntime) compileService(s model.ServiceSpec) ([]byte, error) {
	if k.variant != nil {
		return compiler.CompileAmneziaWG(s)
	}
	return compiler.CompileKernelWireGuard(s)
}
func variantDigest(s model.ServiceSpec) string {
	if s.AmneziaWG == nil {
		return ""
	}
	raw, e := json.Marshal(s.AmneziaWG)
	if e != nil {
		return "invalid"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func newInterfaceEpoch() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func (e *Engine) compile(state model.DesiredState) (receipt, []byte, error) {
	if e.variant == nil {
		return compile(state)
	}
	if state.Generation <= 0 || len(state.Services) > 1 || e.variant.validate(state) != nil {
		return receipt{}, nil, ErrRuntime
	}
	var cfg []byte
	var err error
	if len(state.Services) == 1 {
		cfg, err = compiler.CompileAmneziaWG(state.Services[0])
		if err != nil {
			return receipt{}, nil, err
		}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return receipt{}, nil, err
	}
	sum := sha256.Sum256(raw)
	return receipt{Format: 1, Generation: state.Generation, Digest: hex.EncodeToString(sum[:]), Empty: len(state.Services) == 0}, cfg, nil
}

// ProvisionAmneziaWG is called only by explicit installation of a dedicated
// AmneziaWG node. Ordinary reconciliation does not enable host forwarding.
func ProvisionAmneziaWG(ctx context.Context, base string) error {
	v := amneziaWGVariant(base)
	if e := v.verify(); e != nil {
		return e
	}
	root := filepath.Join(base, "amneziawg")
	if e := privateDirectory(root, true); e != nil {
		return e
	}
	if e := (NFTNetwork{}).ProvisionForwarding(ctx); e != nil {
		return e
	}
	if _, e := os.Lstat(filepath.Join(root, "traffic.json")); os.IsNotExist(e) {
		for _, name := range []string{"checkpoint.json", "interface.json", "process.json"} {
			if _, e := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(e) {
				return ErrTraffic
			}
		}
		ledger, e := OpenTrafficLedger(root)
		if e != nil {
			return e
		}
		epoch, e := newInterfaceEpoch()
		if e != nil {
			return e
		}
		_, _, e = ledger.Sample(epoch, map[string]PeerCounter{})
		return e
	} else {
		return e
	}
}

func OpenAmneziaWG(ctx context.Context, base string) (*Driver, error) {
	v := amneziaWGVariant(base)
	if e := v.verify(); e != nil {
		return nil, e
	}
	root := filepath.Join(base, "amneziawg")
	kernel, e := OpenKernelRuntime(root, NFTNetwork{})
	if e != nil {
		return nil, e
	}
	kernel.variant = v
	if _, _, e = kernel.ledger.Snapshot(); e != nil {
		return nil, e
	}
	engine, e := openEngine(ctx, root, kernel, v)
	if e != nil {
		return nil, e
	}
	return &Driver{kernel: kernel, engine: engine, variant: v}, nil
}

// StopAmneziaWG closes only the process/interface recorded in this private data
// root. It does not open the engine or trust a checkpoint as a running process.
func StopAmneziaWG(ctx context.Context, base string) error {
	v := amneziaWGVariant(base)
	if e := v.verify(); e != nil {
		return e
	}
	kernel, e := OpenKernelRuntime(filepath.Join(base, "amneziawg"), NFTNetwork{})
	if e != nil {
		return e
	}
	kernel.variant = v
	return kernel.Stop(ctx)
}
