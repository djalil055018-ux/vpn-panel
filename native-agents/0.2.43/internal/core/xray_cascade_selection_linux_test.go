//go:build linux

package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestXrayCascadeFloorSurvivesProfileDowngradeAndRestart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned selection")
	}
	ctx := context.Background()
	base := t.TempDir()
	if err := RequireXrayProfileRuntime(ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := RequireXrayCascadeRuntime(ctx, base); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(base, selectionFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range []string{"0.2.23", "0.2.31", "0.2.32", "0.2.33"} {
		if _, err := ReadRuntimeSelection(base, "xray", old); err == nil {
			t.Fatal("old runtime accepted")
		}
		if _, err := SelectRuntimeCore(ctx, base, "xray", old); err == nil {
			t.Fatal("old runtime replaced floor")
		}
	}
	// Removing every cascade and returning to an ordinary imported profile must
	// keep the higher floor, including after the process is started again.
	if err := RequireXrayProfileRuntime(ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := RequireXrayCascadeRuntime(ctx, base); err != nil {
		t.Fatal(err)
	}
	chosen, err := SelectRuntimeCore(ctx, base, "xray", "0.2.34")
	if err != nil || chosen.MinimumAgent != XrayCascadeMinimumAgent {
		t.Fatal("floor lost", err)
	}
	after, _ := os.ReadFile(filepath.Join(base, selectionFile))
	if string(before) != string(after) {
		t.Fatal("floor was rewritten/lowered")
	}
}

func TestXrayCascadeFloorRejectsUnsafeOrCancelledPromotion(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned selection")
	}
	for _, mode := range []string{"cancelled", "different-core", "public", "unknown-floor", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			kind := "xray"
			if mode == "different-core" {
				kind = "hysteria2"
			}
			if _, err := SelectRuntimeCore(ctx, base, kind, "0.2.34"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, selectionFile)
			switch mode {
			case "cancelled":
				cancel()
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "unknown-floor":
				if err := os.WriteFile(path, []byte(`{"format":1,"core":"xray","minimum_agent":"0.2.35"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if os.Rename(path, path+".original") != nil || os.Symlink(path+".original", path) != nil {
					t.Fatal("fixture")
				}
			}
			before, _ := os.ReadFile(path)
			if err := RequireXrayCascadeRuntime(ctx, base); err == nil {
				t.Fatal("unsafe promotion accepted")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("unsafe marker replaced")
			}
		})
	}
}
