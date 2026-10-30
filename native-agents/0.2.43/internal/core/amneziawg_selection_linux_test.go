//go:build linux

package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAmneziaWGSelectionCannotDowngradeOrAdoptAnotherRuntime(t *testing.T) {
	base := selectionBase(t)
	if _, err := SelectRuntimeCore(context.Background(), base, "amneziawg", "0.2.41"); err == nil {
		t.Fatal("old agent accepted")
	}
	got, err := SelectRuntimeCore(context.Background(), base, "amneziawg", "0.2.42")
	if err != nil || got.Core != "amneziawg" || got.MinimumAgent != "0.2.42" {
		t.Fatal("selection", err)
	}
	for _, other := range []string{"wireguard", "xray", "hysteria2", "openvpn", "pptp"} {
		if _, err := ReadRuntimeSelection(base, other, "0.2.42"); err == nil {
			t.Fatal("implicit runtime migration accepted")
		}
	}
	if _, err := ReadRuntimeSelection(base, "", "0.2.41"); err == nil {
		t.Fatal("agent downgrade accepted")
	}
	for _, path := range []string{"amneziawg", "cores/amneziawg"} {
		fresh := selectionBase(t)
		if err := os.MkdirAll(filepath.Join(fresh, path), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadRuntimeSelection(fresh, "amneziawg", "0.2.42"); err == nil {
			t.Fatal("unmarked AWG data silently adopted")
		}
	}
	if err := os.Mkdir(filepath.Join(base, "wireguard"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRuntimeSelection(base, "amneziawg", "0.2.42"); err == nil {
		t.Fatal("conflicting native WireGuard data accepted")
	}
}
