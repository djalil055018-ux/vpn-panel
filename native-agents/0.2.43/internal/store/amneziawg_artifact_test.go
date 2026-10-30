package store

import (
	"testing"
	"vpn-platform/internal/model"
)

func TestAmneziaWGReviewedArtifactCannotBeSubstituted(t *testing.T) {
	correct := []string{"amneziawg", model.AmneziaWGNativeVersion, model.AmneziaWGArtifactSHA256, model.AmneziaWGDownloadURL}
	if !reviewedRuntimeArtifact(correct[0], correct[1], correct[2], correct[3]) {
		t.Fatal("reviewed runtime rejected")
	}
	for _, index := range []int{1, 2, 3} {
		changed := append([]string(nil), correct...)
		changed[index] = "unreviewed"
		if reviewedRuntimeArtifact(changed[0], changed[1], changed[2], changed[3]) {
			t.Fatal("unreviewed native runtime accepted")
		}
	}
}
