package hysteria

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"vpn-platform/internal/model"
)

func TestConfirmedCheckpointPrivateMonotonicAndNoCredentialMaterial(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	_, state := revisionFixture(t)
	checkpoint := confirmedCheckpoint{filepath.Join(t.TempDir(), "confirmed.json")}
	ctx := context.Background()
	if err := checkpoint.commit(ctx, 1, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(checkpoint.path)
	if err != nil || bytes.Contains(raw, []byte(state.Services[0].Clients[0].ID)) || bytes.Contains(raw, []byte(state.Services[0].Clients[0].StatsKey)) {
		t.Fatal("confirmation leaked credentials")
	}
	record, exists, err := checkpoint.read()
	if err != nil || !exists || record.AppliedGeneration != 1 {
		t.Fatal("confirmation unreadable")
	}
	if err := checkpoint.commit(ctx, 1, state); err != nil {
		t.Fatal("identical retry failed")
	}
	changed := state
	changed.Services = append([]model.ServiceSpec(nil), state.Services...)
	changed.Services[0].Port++
	if checkpoint.commit(ctx, 1, changed) == nil {
		t.Fatal("same confirmation changed structure")
	}
	if err := checkpoint.commit(ctx, 2, changed); err != nil {
		t.Fatal(err)
	}
	if checkpoint.commit(ctx, 1, state) == nil {
		t.Fatal("confirmation rewound")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if checkpoint.commit(ctx, 3, changed) == nil {
		t.Fatal("cancelled confirmation wrote")
	}
	after, _, _ := checkpoint.read()
	if after.AppliedGeneration != 2 {
		t.Fatal("rejected commit changed confirmation")
	}
}

func TestConfirmedCheckpointDamageAndUnsafeFilesAreNotReplaced(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	for _, kind := range []string{"corrupt", "public", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			_, state := revisionFixture(t)
			checkpoint := confirmedCheckpoint{filepath.Join(t.TempDir(), "confirmed.json")}
			if checkpoint.commit(context.Background(), 1, state) != nil {
				t.Fatal("fixture failed")
			}
			switch kind {
			case "corrupt":
				os.WriteFile(checkpoint.path, []byte(`{}`), 0600)
			case "public":
				os.Chmod(checkpoint.path, 0644)
			case "symlink":
				os.Rename(checkpoint.path, checkpoint.path+".original")
				os.Symlink(checkpoint.path+".original", checkpoint.path)
			}
			before, _ := os.Lstat(checkpoint.path)
			if checkpoint.commit(context.Background(), 2, state) == nil {
				t.Fatal("damaged confirmation repaired implicitly")
			}
			after, _ := os.Lstat(checkpoint.path)
			if !os.SameFile(before, after) {
				t.Fatal("damaged evidence replaced")
			}
		})
	}
}
