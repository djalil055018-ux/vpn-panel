//go:build linux

package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestXrayProfileRuntimeFloorIsPermanent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned selection")
	}
	base := t.TempDir()
	if _, err := SelectRuntimeCore(context.Background(), base, "xray", "0.2.30"); err != nil {
		t.Fatal(err)
	}
	if err := RequireXrayProfileRuntime(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, selectionFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private durable selection", err)
	}
	var record RuntimeSelection
	if json.Unmarshal(raw, &record) != nil || record.MinimumAgent != "0.2.31" {
		t.Fatal("profile minimum not persisted")
	}
	// Agent30 compares the marker against this exact original Xray selection.
	legacy, _ := selection("xray")
	if record == legacy {
		t.Fatal("legacy Agent would accept imported runtime")
	}
	for _, version := range []string{"0.2.23", "0.2.27", "0.2.30"} {
		if _, err := ReadRuntimeSelection(base, "xray", version); err == nil {
			t.Fatal("old Agent accepted", version)
		}
		if _, err := SelectRuntimeCore(context.Background(), base, "xray", version); err == nil {
			t.Fatal("old Agent lowered marker", version)
		}
	}
	for _, version := range []string{"0.2.31", "0.2.32"} {
		chosen, err := SelectRuntimeCore(context.Background(), base, "xray", version)
		if err != nil || chosen.MinimumAgent != "0.2.31" {
			t.Fatal("compatible restart", err)
		}
	}
	if err := RequireXrayProfileRuntime(context.Background(), base); err != nil {
		t.Fatal("repeat", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("minimum changed after restart")
	}
}

func TestXrayProfileRuntimeFloorRejectsUnsafeMarker(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned selection")
	}
	for _, kind := range []string{"cancelled", "different-core", "corrupt", "public", "symlink", "unknown-floor"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			selected := "xray"
			if kind == "different-core" {
				selected = "hysteria2"
			}
			if _, err := SelectRuntimeCore(context.Background(), base, selected, "0.2.31"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(base, selectionFile)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "cancelled":
				cancel()
			case "corrupt":
				if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := path + ".original"
				if os.Rename(path, target) != nil || os.Symlink(target, path) != nil {
					t.Fatal("fixture")
				}
			case "unknown-floor":
				raw, _ := json.Marshal(RuntimeSelection{1, "xray", "0.2.32"})
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			info, _ := os.Lstat(path)
			if err := RequireXrayProfileRuntime(ctx, base); err == nil {
				t.Fatal("unsafe promotion accepted")
			}
			after, _ := os.ReadFile(path)
			afterInfo, _ := os.Lstat(path)
			if string(before) != string(after) || info.Mode() != afterInfo.Mode() {
				t.Fatal("unsafe marker replaced")
			}
		})
	}
}
