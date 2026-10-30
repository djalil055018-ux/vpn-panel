package store

import "testing"

func TestHysteriaOperationalAgentFloor(t *testing.T) {
	for _, value := range []string{
		"0.2.25",
		"0.2.26",
		"0.3.0",
		"1.0.0",
	} {
		if !HysteriaAgentOperationallyCompatible(value) {
			t.Fatalf("compatible version rejected: %s", value)
		}
	}

	for _, value := range []string{
		"",
		"0.2.24",
		"0.2.23",
		"0.1.99",
		"0.02.25",
		"0.2.025",
		"v0.2.25",
		"0.2.25-rc1",
		"0.2.25.0",
	} {
		if HysteriaAgentOperationallyCompatible(value) {
			t.Fatalf("unsafe or invalid version accepted: %s", value)
		}
	}
}
