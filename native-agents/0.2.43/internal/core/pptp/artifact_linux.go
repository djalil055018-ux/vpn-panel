//go:build linux

package pptp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"vpn-platform/internal/model"
)

const RuntimePath = "/opt/vpn-platform-pptp"
const runtimeBinary = RuntimePath + "/sbin/accel-pppd"

func VerifyArtifact(ctx context.Context) error {
	for p := RuntimePath; p != "/"; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode().Perm()&0022 != 0 {
			return ErrRuntime
		}
		owner, ok := i.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return ErrRuntime
		}
	}
	manifestPath := filepath.Join(RuntimePath, "manifest.json")
	info, err := os.Lstat(manifestPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32<<10 {
		return ErrRuntime
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return ErrRuntime
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != model.PPTPManifestSHA256 {
		return ErrRuntime
	}
	var manifest struct {
		Format  int    `json:"format"`
		Version string `json:"version"`
		Files   []struct {
			Path   string `json:"path"`
			Mode   uint32 `json:"mode"`
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.Format != 1 || manifest.Version != model.PPTPPinnedVersion || len(manifest.Files) != 16 {
		return ErrRuntime
	}
	expected := map[string]bool{"manifest.json": true}
	for _, entry := range manifest.Files {
		if filepath.IsAbs(entry.Path) || filepath.Clean(entry.Path) != entry.Path || strings.HasPrefix(entry.Path, "..") || expected[entry.Path] || entry.Size < 1 || entry.Size > 4<<20 {
			return ErrRuntime
		}
		expected[entry.Path] = true
		path := filepath.Join(RuntimePath, entry.Path)
		f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			return ErrRuntime
		}
		i, e := f.Stat()
		if e != nil {
			f.Close()
			return ErrRuntime
		}
		owner, ok := i.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || !i.Mode().IsRegular() || uint32(i.Mode().Perm()) != entry.Mode || i.Size() != entry.Size {
			f.Close()
			return ErrRuntime
		}
		h := sha256.New()
		_, e = io.Copy(h, io.LimitReader(f, entry.Size+1))
		f.Close()
		if e != nil || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return ErrRuntime
		}
	}
	if err = filepath.WalkDir(RuntimePath, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return ErrRuntime
		}
		i, e := d.Info()
		if e != nil {
			return ErrRuntime
		}
		owner, ok := i.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || i.Mode().Perm()&0022 != 0 || i.Mode()&os.ModeSymlink != 0 {
			return ErrRuntime
		}
		if !d.IsDir() {
			rel, e := filepath.Rel(RuntimePath, path)
			if e != nil || !expected[rel] {
				return ErrRuntime
			}
		}
		return nil
	}); err != nil {
		return err
	}
	raw, err = exec.CommandContext(ctx, runtimeBinary, "--version").Output()
	if err != nil || strings.TrimSpace(string(raw)) != "accel-ppp 1.14.0" {
		return ErrRuntime
	}
	return nil
}
