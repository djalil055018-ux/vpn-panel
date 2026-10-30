package hysteria

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

func testELF(machine uint16) []byte {
	raw := make([]byte, 64)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(raw[16:], 2)
	binary.LittleEndian.PutUint16(raw[18:], machine)
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint16(raw[52:], 64)
	return raw
}
func testInstaller(t *testing.T, raw []byte, handler http.Handler) (*Installer, model.CoreRelease) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	i, err := NewInstaller(base)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	i.pin = artifactPin{PinnedVersion, hex.EncodeToString(sum[:]), server.URL, int64(len(raw))}
	return i, model.CoreRelease{Type: "hysteria2", Version: i.pin.version, SHA256: i.pin.sha256, DownloadURL: i.pin.url}
}
func assertNoStagingFiles(t *testing.T, base string) {
	t.Helper()
	err := filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), ".artifact-") {
			t.Error("staging file retained")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestInstallerPinnedAtomicAndIdempotent(t *testing.T) {
	raw := testELF(62)
	requests := 0
	i, release := testInstaller(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; _, _ = w.Write(raw) }))
	path, err := i.Install(context.Background(), release)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0555 {
		t.Fatal("installed executable permissions invalid")
	}
	if _, err := os.Lstat(filepath.Join(i.base, "cores", "hysteria2", "current")); !os.IsNotExist(err) {
		t.Fatal("installer activated a version")
	}
	second, err := i.Install(context.Background(), release)
	if err != nil || second != path || requests != 1 {
		t.Fatal("idempotent install fetched or changed artifact")
	}
	assertNoStagingFiles(t, i.base)
}
func TestInstallerRejectsInvalidArtifactWithoutPublication(t *testing.T) {
	valid := testELF(62)
	for name, raw := range map[string][]byte{"wrong_hash": bytes.Repeat([]byte("x"), len(valid)), "truncated": valid[:32], "oversized": append(append([]byte{}, valid...), 1)} {
		t.Run(name, func(t *testing.T) {
			i, release := testInstaller(t, valid, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) }))
			if _, err := i.Install(context.Background(), release); err == nil {
				t.Fatal("invalid download accepted")
			}
			target, _ := i.destination(release)
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatal("invalid artifact published")
			}
			assertNoStagingFiles(t, i.base)
		})
	}
	raw := testELF(183)
	i, release := testInstaller(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) }))
	if _, err := i.Install(context.Background(), release); err == nil {
		t.Fatal("valid hash with wrong architecture accepted")
	}
}
func TestInstallerRejectsUnpinnedMetadataAndCancellation(t *testing.T) {
	raw := testELF(62)
	i, release := testInstaller(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("invalid metadata reached download") }))
	for _, change := range []func(*model.CoreRelease){func(r *model.CoreRelease) { r.Type = "xray" }, func(r *model.CoreRelease) { r.Version = "../../escape" }, func(r *model.CoreRelease) { r.SHA256 = strings.Repeat("0", 64) }, func(r *model.CoreRelease) { r.DownloadURL = "http://127.0.0.1/private" }} {
		copy := release
		change(&copy)
		if _, err := i.Install(context.Background(), copy); err == nil {
			t.Fatal("unpinned artifact accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := i.Install(ctx, release); err == nil {
		t.Fatal("cancelled download accepted")
	}
	entries, _ := os.ReadDir(i.base)
	if len(entries) != 0 {
		t.Fatal("rejected request changed staging tree")
	}
}
func TestInstallerPreservesCorruptExistingVersion(t *testing.T) {
	raw := testELF(62)
	i, release := testInstaller(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("corrupt existing version fetched replacement") }))
	target, _ := i.destination(release)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	old := []byte("old-corrupt-artifact")
	if err := os.WriteFile(target, old, 0555); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Install(context.Background(), release); err == nil {
		t.Fatal("corrupt cache accepted")
	}
	after, _ := os.ReadFile(target)
	if !bytes.Equal(old, after) {
		t.Fatal("corrupt installed version replaced without rollback guard")
	}
}
func TestInstallerRejectsSymlinkAndWritableDirectory(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		raw := testELF(62)
		i, release := testInstaller(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unsafe staging tree reached network") }))
		if symlink {
			if err := os.Symlink(t.TempDir(), filepath.Join(i.base, "cores")); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Mkdir(filepath.Join(i.base, "cores"), 0777); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(i.base, "cores"), 0777); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := i.Install(context.Background(), release); err == nil {
			t.Fatal("unsafe staging path accepted")
		}
	}
}
func TestInstallerRejectsUntrustedRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted redirect followed") }))
	defer destination.Close()
	i, release := testInstaller(t, testELF(62), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	if _, err := i.Install(context.Background(), release); err == nil {
		t.Fatal("untrusted redirect accepted")
	}
}
