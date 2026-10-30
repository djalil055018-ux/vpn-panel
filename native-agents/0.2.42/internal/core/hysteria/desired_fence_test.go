package hysteria

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"vpn-platform/internal/model"
)

func TestDesiredFenceBindsStructureAndCredentialsWithoutPersistingThem(t *testing.T) {
	_, state := revisionFixture(t)
	ctx := context.Background()
	fence := desiredFence{filepath.Join(t.TempDir(), "desired.json")}
	if err := fence.commit(ctx, state, 0); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fence.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(state.Services[0].Clients[0].ID)) || bytes.Contains(raw, []byte(state.Services[0].TLS.CertificateID)) {
		t.Fatal("desired checkpoint contains raw desired material")
	}
	same := state
	same.Core.Channel = "different-release-label"
	if err = fence.check(same, 1); err != nil {
		t.Fatal("channel label broke replay")
	}
	for _, kind := range []string{"port", "clients", "certificate"} {
		t.Run(kind, func(t *testing.T) {
			changed := state
			changed.Services = append([]model.ServiceSpec(nil), state.Services...)
			switch kind {
			case "port":
				changed.Services[0].Port++
			case "clients":
				changed.Services[0].Clients = nil
			case "certificate":
				copy := *changed.Services[0].TLS
				copy.CertificateID = "99999999-9999-4999-8999-999999999999"
				changed.Services[0].TLS = &copy
			}
			if err := fence.check(changed, 1); !errors.Is(err, ErrAccessConflict) {
				t.Fatal("same generation accepted different desired state")
			}
		})
	}
	state.Generation = 2
	if err = fence.commit(ctx, state, 1); err != nil {
		t.Fatal(err)
	}
	state.Generation = 1
	if err = fence.check(state, 1); !errors.Is(err, ErrAccessConflict) {
		t.Fatal("stale generation accepted")
	}
	reopened := desiredFence{fence.path}
	record, err := reopened.read(2)
	if err != nil || record.Generation != 2 {
		t.Fatal("generation checkpoint lost on reopen")
	}
}
func TestDesiredFenceDamageAndMissingAppliedRecordFailClosed(t *testing.T) {
	_, state := revisionFixture(t)
	fence := desiredFence{filepath.Join(t.TempDir(), "desired.json")}
	if _, err := fence.read(1); !errors.Is(err, ErrDesiredFence) {
		t.Fatal("missing applied checkpoint accepted")
	}
	if err := fence.commit(context.Background(), state, 0); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fence.path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"generation":1`), []byte(`"generation":2`), 1)
	if os.WriteFile(fence.path, raw, 0600) != nil {
		t.Fatal("corruption fixture failed")
	}
	if _, err = fence.read(1); !errors.Is(err, ErrDesiredFence) {
		t.Fatal("checksum mismatch accepted")
	}
}
