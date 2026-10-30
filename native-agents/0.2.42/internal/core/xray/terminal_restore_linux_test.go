//go:build linux

package xray

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

func TestTerminalRestoreRequiresExactUnblockedReceipt(t *testing.T) {
	d := New(t.TempDir())
	for _, path := range []string{d.xrayDir(), d.coresDir()} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("1.2.3", d.currentLink()); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"inbounds":[]}`)
	if err := os.WriteFile(d.configPath(), config, 0600); err != nil {
		t.Fatal(err)
	}
	a := model.AgentAssignment{DeploymentStatus: "healthy", NodeAppliedGeneration: 5, AppliedCoreVersion: "1.2.3", DesiredState: model.DesiredState{Generation: 5, Core: model.CoreRelease{Type: "xray", Version: "1.2.3"}}}
	intent, err := d.accessIntent(a.DesiredState)
	if err != nil {
		t.Fatal(err)
	}
	intent.ConfigSHA256 = configDigest(config)
	if err = d.writeAccessFence(intent); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("XRAY_TEST_CALLS", filepath.Join(bin, "calls"))
	t.Setenv("XRAY_TEST_ACTIVE", filepath.Join(bin, "active"))
	script := "#!/bin/sh\necho \"$*\" >> \"$XRAY_TEST_CALLS\"\ncase \"$1\" in\nis-active) test -f \"$XRAY_TEST_ACTIVE\";;\nstart) touch \"$XRAY_TEST_ACTIVE\";;\n*) exit 0;;\nesac\n"
	if err = os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	invalid := []model.AgentAssignment{a, a, a}
	invalid[0].DeploymentStatus = "failed"
	invalid[1].NodeAppliedGeneration = 4
	invalid[2].AppliedCoreVersion = "1.2.2"
	for _, v := range invalid {
		if d.RestoreTerminalAssignment(context.Background(), v) == nil {
			t.Fatal("unconfirmed assignment restored")
		}
	}
	intent.Blocked = true
	d.writeAccessFence(intent)
	if d.RestoreTerminalAssignment(context.Background(), a) == nil {
		t.Fatal("failed revoke fence reopened")
	}
	intent.Blocked = false
	intent.Generation = 6
	d.writeAccessFence(intent)
	if d.RestoreTerminalAssignment(context.Background(), a) == nil {
		t.Fatal("older authorization restored")
	}
	intent.Generation = 5
	d.writeAccessFence(intent)
	os.WriteFile(d.configPath(), []byte("changed"), 0600)
	if d.RestoreTerminalAssignment(context.Background(), a) == nil {
		t.Fatal("mismatched config restored")
	}
	if _, err = os.Stat(filepath.Join(bin, "calls")); !os.IsNotExist(err) {
		t.Fatal("rejected receipt reached service manager")
	}
	os.WriteFile(d.configPath(), config, 0600)
	if err = d.RestoreTerminalAssignment(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err = d.RestoreTerminalAssignment(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(filepath.Join(bin, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(calls), "\nstart vpn-platform-xray.service\n") != 1 {
		t.Fatal("healthy runtime restarted or missing start")
	}
}
