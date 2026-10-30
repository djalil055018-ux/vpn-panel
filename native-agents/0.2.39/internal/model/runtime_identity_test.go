package model

import "testing"

func TestHysteriaAgentReleaseFloor(t *testing.T) {
	for _, version := range []string{"0.2.24", "0.2.25", "0.3.0", "1.0.0"} {
		if !HysteriaAgentCompatible(version) {
			t.Fatal("compatible release rejected")
		}
	}
	for _, version := range []string{"", "0.2.23", "0.1.99", "0.02.24", "0.2.024", "+1.0.0", "v0.2.24", "0.2.24-rc1", "0.2.24.0", "999999999999999999.0.0"} {
		if HysteriaAgentCompatible(version) {
			t.Fatal("invalid or older release accepted")
		}
	}
}

func TestCertificateDeletionAgentReleaseFloor(t *testing.T) {
	for _, version := range []string{"0.2.36", "0.2.37", "0.3.0", "1.0.0"} {
		if !CertificateDeletionAgentCompatible(version) {
			t.Fatal("compatible agent rejected", version)
		}
	}
	for _, version := range []string{"", "0.2.35", "0.1.99", "0.02.36", "0.2.036", "v0.2.36", "0.2.36-rc1"} {
		if CertificateDeletionAgentCompatible(version) {
			t.Fatal("unsupported agent accepted", version)
		}
	}
}
