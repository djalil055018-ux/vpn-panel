//go:build linux

package hysteria

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRuntimeSettingsConcurrentCreationAndRestartPreserveIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership")
	}
	base := t.TempDir()
	var wg sync.WaitGroup
	results := make(chan runtimeSettings, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			settings, err := openRuntimeSettings(base, 65534, 65534)
			if err != nil {
				t.Error(err)
				return
			}
			results <- settings
		}()
	}
	wg.Wait()
	close(results)
	var first runtimeSettings
	for settings := range results {
		if first.Format == 0 {
			first = settings
		}
		if first != settings {
			t.Fatal("concurrent settings creation produced inconsistent records")
		}
	}
	again, err := openRuntimeSettings(base, 65534, 65534)
	if err != nil || again != first || first.AuthPort == first.StatisticsPort || len(first.StatisticsSecret) != 64 {
		t.Fatal("settings did not survive restart")
	}
	path := filepath.Join(base, "hysteria2", "control", "settings.json")
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("settings are not private")
	}
	if _, err = openRuntimeSettings(base, 65533, 65534); err == nil {
		t.Fatal("changed managed identity accepted")
	}
	if _, err = openRuntimeSettings(base, 65534, 65533); err == nil {
		t.Fatal("changed managed group accepted")
	}
	rootInfo, err := os.Stat(filepath.Join(base, "hysteria2"))
	if err != nil || !ownedBy(rootInfo, 0, 65534) {
		t.Fatal("identity rejection changed runtime ownership")
	}
	after, err := openRuntimeSettings(base, 65534, 65534)
	if err != nil || after != first {
		t.Fatal("identity rejection changed settings")
	}
}
func TestRuntimeSettingsMissingBesideCurrentRevisionFailsClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership")
	}
	base := t.TempDir()
	if _, err := openRuntimeSettings(base, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "hysteria2", "control", "settings.json")
	if os.Remove(path) != nil || os.Symlink("revisions/old", filepath.Join(base, "hysteria2", "current")) != nil {
		t.Fatal("fixture failed")
	}
	if _, err := openRuntimeSettings(base, 65534, 65534); err == nil {
		t.Fatal("missing live settings silently regenerated")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("missing live settings path changed")
	}
}
func TestRuntimeSettingsRejectUnsafeExistingRecordsWithoutRegeneration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership")
	}
	for _, kind := range []string{"corrupt", "public", "symlink", "public_parent"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			if _, err := openRuntimeSettings(base, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, "hysteria2", "control", "settings.json")
			switch kind {
			case "corrupt":
				if os.WriteFile(path, []byte(`{}`), 0600) != nil {
					t.Fatal("fixture failed")
				}
			case "public":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("fixture failed")
				}
			case "symlink":
				if os.Rename(path, path+".original") != nil || os.Symlink(path+".original", path) != nil {
					t.Fatal("fixture failed")
				}
			case "public_parent":
				if os.Chmod(filepath.Dir(path), 0755) != nil {
					t.Fatal("fixture failed")
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = openRuntimeSettings(base, 65534, 65534); err == nil {
				t.Fatal("unsafe existing record accepted")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("unsafe record silently replaced")
			}
		})
	}
}
