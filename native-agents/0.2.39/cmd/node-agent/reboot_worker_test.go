package main

import "testing"

func TestNodeRebootUnitNameAcceptsOnlyUUID(t *testing.T) {
	unit, ok := nodeRebootUnitName("d88503f9-aed9-489f-a599-1e4ccf637c4e")
	if !ok || unit != "vpn-platform-node-reboot-d88503f9-aed9-489f-a599-1e4ccf637c4e" {
		t.Fatalf("unexpected unit name: %q, %t", unit, ok)
	}
	for _, input := range []string{"", "../../reboot", "00000000-0000-0000-0000-000000000000; reboot", "$(id)"} {
		if _, ok := nodeRebootUnitName(input); ok {
			t.Fatalf("accepted unsafe reboot job identity %q", input)
		}
	}
}
