//go:build linux

package main

import (
	"context"
	"os"
	"testing"
	"vpn-platform/internal/core"
)

func TestLocalCommandRejectsUnknownOrIncompleteInputBeforeStartup(t *testing.T) {
	if handled, err := runLocalCommand(nil); handled || err != nil {
		t.Fatal("normal startup intercepted")
	}
	for _, args := range [][]string{{"unknown"}, {"capture-traffic"}, {"capture-traffic", "--data-dir", "/", "extra"}, {"capture-traffic", "--secret", "must-not-be-printed"}, {"--version", "extra"}} {
		if handled, err := runLocalCommand(args); !handled || err == nil {
			t.Fatal("invalid local command accepted")
		}
	}
}

func TestProvisionCommandRejectsMissingExplicitCoreAndOwnedNode(t *testing.T) {
	for _, args := range [][]string{nil, {"--data-dir", "/tmp"}, {"--core", "xray", "--data-dir", "/tmp"}, {"--core", "hysteria2", "--data-dir", "/tmp", "--ownership-fd", "1"}} {
		if runProvisionCommand(args) == nil {
			t.Fatal("invalid provisioning command accepted")
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	base := t.TempDir()
	release, err := core.AcquireNodeOwnership(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if runProvisionCommand([]string{"--core", "hysteria2", "--data-dir", base}) == nil {
		t.Fatal("provisioned an owned node")
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected provisioning changed state")
	}
}
