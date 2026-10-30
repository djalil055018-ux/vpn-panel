package model

import "testing"

func TestReviewedHysteriaTuplesCannotBeMixed(t *testing.T) {
	versions := []string{HysteriaPinnedVersion, HysteriaLegacyVersion}
	hashes := []string{HysteriaPinnedSHA256, HysteriaLegacySHA256}
	urls := []string{HysteriaPinnedDownloadURL, HysteriaLegacyDownloadURL}
	for v, version := range versions {
		for h, sha := range hashes {
			for u, url := range urls {
				want := v == h && h == u
				if ReviewedHysteriaArtifact(version, sha, url) != want {
					t.Fatal("mixed reviewed versions crossed the artifact boundary")
				}
			}
		}
	}
	if ReviewedHysteriaArtifact("../../escape", HysteriaPinnedSHA256, HysteriaPinnedDownloadURL) || ReviewedHysteriaArtifact(HysteriaPinnedVersion, HysteriaPinnedSHA256, "http://127.0.0.1/private") {
		t.Fatal("unreviewed path or URL accepted")
	}
}

func TestHysteriaCoreUpgradeRequiresNewAgentButLegacyRemainsUsable(t *testing.T) {
	for _, test := range []struct {
		core, agent string
		want        bool
	}{
		{HysteriaLegacyVersion, "0.2.24", false},
		{HysteriaLegacyVersion, "0.2.25", true},
		{HysteriaLegacyVersion, "0.2.42", true},
		{HysteriaPinnedVersion, "0.2.42", false},
		{HysteriaPinnedVersion, "0.2.43", true},
		{HysteriaPinnedVersion, "0.2.044", false},
		{HysteriaPinnedVersion, "0.2.44", true},
		{"unknown", "0.2.43", false},
	} {
		if HysteriaReleaseAgentCompatible(test.core, test.agent) != test.want {
			t.Fatal("core upgrade changed the legacy or minimum-agent boundary")
		}
	}
}
