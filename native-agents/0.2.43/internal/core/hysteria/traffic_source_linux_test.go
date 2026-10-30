//go:build linux

package hysteria

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoredTrafficSourceIsReadOnlyAndRejectsDamagedSettings(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	for _, kind := range []string{"valid", "missing", "corrupt", "public", "symlink", "public_parent"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			if _, err := openRuntimeSettings(base, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, "hysteria2", "control", "settings.json")
			switch kind {
			case "missing":
				os.Remove(path)
			case "corrupt":
				os.WriteFile(path, []byte(`{}`), 0600)
			case "public":
				os.Chmod(path, 0644)
			case "symlink":
				os.Rename(path, path+".original")
				os.Symlink(path+".original", path)
			case "public_parent":
				os.Chmod(filepath.Dir(path), 0755)
			}
			before, _ := os.Lstat(path)
			rawBefore, _ := os.ReadFile(path)
			stats, epoch, err := OpenStoredTrafficSource(base, ManagedService, true)
			if kind == "valid" {
				if err != nil || stats == nil || epoch == nil {
					t.Fatal("stored source rejected")
				}
			} else if err == nil {
				t.Fatal("damaged source accepted")
			}
			after, statErr := os.Lstat(path)
			rawAfter, _ := os.ReadFile(path)
			if kind == "missing" {
				if !os.IsNotExist(statErr) {
					t.Fatal("missing settings regenerated")
				}
			} else if statErr != nil || !os.SameFile(before, after) || string(rawBefore) != string(rawAfter) {
				t.Fatal("read changed stored settings")
			}
		})
	}
}
