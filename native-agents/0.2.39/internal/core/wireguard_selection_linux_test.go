//go:build linux

package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeWireGuardSelectionRequiresNewAgentAndPreservesRuntime(t *testing.T) {
	base := selectionBase(t)
	if _, err := SelectRuntimeCore(context.Background(), base, "wireguard", "0.2.27"); err == nil {
		t.Fatal("old agent selected native runtime")
	}
	chosen, err := SelectRuntimeCore(context.Background(), base, "wireguard", "0.2.28")
	if err != nil || chosen.Core != "wireguard" || chosen.MinimumAgent != "0.2.28" {
		t.Fatal("selection", err)
	}
	for _, input := range [][2]string{{"", "0.2.27"}, {"xray", "0.2.28"}, {"openvpn", "0.2.28"}} {
		if _, err = ReadRuntimeSelection(base, input[0], input[1]); err == nil {
			t.Fatal("downgrade or implicit migration accepted")
		}
	}
	fresh := selectionBase(t)
	if err = os.Mkdir(filepath.Join(fresh, "wireguard"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadRuntimeSelection(fresh, "", "0.2.28"); err == nil {
		t.Fatal("missing marker treated as fresh Xray")
	}
}
