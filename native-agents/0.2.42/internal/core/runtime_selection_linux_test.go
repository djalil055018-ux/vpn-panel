//go:build linux

package core

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func selectionBase(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root ownership")
	}
	return t.TempDir()
}
func TestSelectionPreservesExplicitCoreAcrossRestartAndRejectsDowngrade(t *testing.T) {
	base := selectionBase(t)
	chosen, err := SelectRuntimeCore(context.Background(), base, "hysteria2", "0.2.24")
	if err != nil || chosen.Core != "hysteria2" {
		t.Fatal("initial selection failed", err)
	}
	record, err := ReadRuntimeSelection(base, "", "0.2.25")
	if err != nil || record != chosen {
		t.Fatal("restart default changed explicit core")
	}
	for _, input := range [][2]string{{"xray", "0.2.24"}, {"", "0.2.23"}, {"hysteria2", "invalid"}} {
		if _, err = SelectRuntimeCore(context.Background(), base, input[0], input[1]); err == nil {
			t.Fatal("core migration or incompatible downgrade accepted")
		}
	}
	info, err := os.Lstat(filepath.Join(base, selectionFile))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("selection is not private")
	}
}
func TestLegacyXrayCannotBeImplicitlyOrExplicitlySwitched(t *testing.T) {
	base := selectionBase(t)
	if os.Mkdir(filepath.Join(base, "xray"), 0700) != nil {
		t.Fatal("fixture failed")
	}
	if _, err := SelectRuntimeCore(context.Background(), base, "hysteria2", "0.2.24"); err == nil {
		t.Fatal("legacy Xray converted without migration")
	}
	chosen, err := SelectRuntimeCore(context.Background(), base, "", "0.2.24")
	if err != nil || chosen.Core != "xray" {
		t.Fatal("legacy Xray compatibility lost")
	}
}
func TestMissingOrDamagedHysteriaSelectionFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "public", "symlink", "weakened_floor"} {
		t.Run(kind, func(t *testing.T) {
			base := selectionBase(t)
			path := filepath.Join(base, selectionFile)
			if _, err := SelectRuntimeCore(context.Background(), base, "hysteria2", "0.2.24"); err != nil {
				t.Fatal(err)
			}
			if os.Mkdir(filepath.Join(base, "hysteria2"), 0750) != nil {
				t.Fatal("fixture failed")
			}
			switch kind {
			case "missing":
				if os.Remove(path) != nil {
					t.Fatal("fixture failed")
				}
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
			case "weakened_floor":
				if os.WriteFile(path, []byte(`{"format":1,"core":"hysteria2","minimum_agent":"0.0.1"}`), 0600) != nil {
					t.Fatal("fixture failed")
				}
			}
			if _, err := ReadRuntimeSelection(base, "", "0.2.24"); err == nil {
				t.Fatal("damaged Hysteria node defaulted to Xray")
			}
		})
	}
}
func TestConcurrentSelectionNeverOverwritesWinningCore(t *testing.T) {
	base := selectionBase(t)
	var wg sync.WaitGroup
	results := make(chan RuntimeSelection, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			requested := "xray"
			if index%2 == 0 {
				requested = "hysteria2"
			}
			record, err := SelectRuntimeCore(context.Background(), base, requested, "0.2.24")
			if err == nil {
				if record.Core != requested {
					t.Error("caller silently adopted a different core")
				}
				results <- record
			}
		}(i)
	}
	wg.Wait()
	close(results)
	final, err := ReadRuntimeSelection(base, "", "0.2.24")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for record := range results {
		count++
		if record != final {
			t.Fatal("two different selections were published")
		}
	}
	if count == 0 {
		t.Fatal("no winner")
	}
}
func TestCancelledSelectionCreatesNoMarker(t *testing.T) {
	base := selectionBase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SelectRuntimeCore(ctx, base, "xray", "0.2.24"); err == nil {
		t.Fatal("cancelled selection accepted")
	}
	if _, err := os.Lstat(filepath.Join(base, selectionFile)); !os.IsNotExist(err) {
		t.Fatal("cancelled selection changed disk")
	}
}

func TestSelectionRejectsConflictingRuntimeMaterialAndOrphanedBinary(t *testing.T) {
	for _, selected := range []string{"xray", "hysteria2"} {
		t.Run(selected, func(t *testing.T) {
			base := selectionBase(t)
			if _, err := SelectRuntimeCore(context.Background(), base, selected, "0.2.24"); err != nil {
				t.Fatal(err)
			}
			other := "xray"
			if selected == "xray" {
				other = "hysteria2"
			}
			if os.MkdirAll(filepath.Join(base, "cores", other), 0755) != nil {
				t.Fatal("fixture failed")
			}
			if _, err := ReadRuntimeSelection(base, "", "0.2.24"); err == nil {
				t.Fatal("mixed core state accepted")
			}
		})
	}
	base := selectionBase(t)
	if os.MkdirAll(filepath.Join(base, "cores", "hysteria2"), 0755) != nil {
		t.Fatal("fixture failed")
	}
	if _, err := ReadRuntimeSelection(base, "", "0.2.24"); err == nil {
		t.Fatal("orphaned Hysteria binary defaulted to Xray")
	}
}
