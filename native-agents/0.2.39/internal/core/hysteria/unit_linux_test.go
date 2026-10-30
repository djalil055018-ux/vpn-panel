//go:build linux

package hysteria

import (
	"strings"
	"testing"
)

func TestManagedUnitStopCaptureHasFixedRootHelperAndBoundedTimeout(t *testing.T) {
	raw, err := renderManagedUnit("/var/lib/vpn-platform", 65534, 65534, ManagedAgentService)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{"User=65534\n", "ExecStop=+/usr/local/bin/vpn-node-agent capture-traffic --data-dir /var/lib/vpn-platform --unit %n\n", "TimeoutStopSec=15\n", "KillMode=control-group\n"} {
		if !strings.Contains(text, required) {
			t.Fatal("managed stop/privilege contract missing")
		}
	}
	for _, binary := range []string{"/", "relative", "/opt/../bin/agent", "/opt/agent\nUser=root", "/opt/%n", "/opt/with space"} {
		if _, err := renderManagedUnitWithAgent("/var/lib/vpn-platform", 65534, 65534, ManagedAgentService, binary); err == nil {
			t.Fatal("helper directive injection accepted")
		}
	}
}

func TestManagedUnitRejectsPrivilegeAndDirectiveInjection(t *testing.T) {
	for _, base := range []string{"/", "relative", "/opt/../etc", "/opt/runtime\nUser=root", "/opt/%n", "/opt/$NAME", "/opt/white space"} {
		if _, err := renderManagedUnit(base, 65534, 65534, ManagedAgentService); err == nil {
			t.Fatal("unsafe executable path accepted")
		}
	}
	for _, owner := range []string{"ssh.service", "vpn-platform-node-agent.service\nUser=root", "../agent.service"} {
		if _, err := renderManagedUnit("/var/lib/vpn-platform", 65534, 65534, owner); err == nil {
			t.Fatal("unmanaged owner accepted")
		}
	}
	for _, ids := range [][2]int{{0, 65534}, {65534, 0}, {-1, 65534}, {1 << 32, 65534}} {
		if _, err := renderManagedUnit("/var/lib/vpn-platform", ids[0], ids[1], ManagedAgentService); err == nil {
			t.Fatal("privileged/overflow identity accepted")
		}
	}
	if _, err := renderManagedUnit("/var/lib/vpn-platform", 65534, 65534, ManagedAgentService); err != nil {
		t.Fatal(err)
	}
}
