package store

import "testing"

func fencedFacts() recoveryAttemptFacts {
	return recoveryAttemptFacts{
		SourceStatus:         "applying",
		SourceExecutionID:    "execution-17",
		SourceExecutionEpoch: 17,

		LeaseState:           "fenced",
		LeaseExecutionID:     "execution-17",
		LeaseExecutionEpoch:  17,
		LeaseOwnerInstanceID: "agent-instance",

		FenceState:                    "acknowledged",
		FenceExecutionID:              "execution-17",
		FenceExecutionEpoch:           17,
		FenceTargetOwnerInstanceID:    "agent-instance",
		FenceAcknowledgedByInstanceID: "agent-instance",

		LiveReleaseID:      "live-release",
		LiveReleaseType:    "xray",
		LiveReleaseVersion: "26.7.28",
		LiveReleaseChannel: "canary",
	}
}

func TestRecoverySourcePhysicallyFencedExactIdentity(
	t *testing.T,
) {
	facts := fencedFacts()

	if !recoverySourcePhysicallyFenced(
		facts,
	) {
		t.Fatal(
			"expected exact fenced execution proof",
		)
	}
}

func TestRecoverySourcePhysicalFenceRejectsOwnerMismatch(
	t *testing.T,
) {
	facts := fencedFacts()

	facts.FenceAcknowledgedByInstanceID =
		"other-agent"

	if recoverySourcePhysicallyFenced(
		facts,
	) {
		t.Fatal(
			"owner mismatch must invalidate fence proof",
		)
	}
}

func TestRecoverySourcePhysicalFenceRejectsExecutionMismatch(
	t *testing.T,
) {
	facts := fencedFacts()

	facts.FenceExecutionID =
		"other-execution"

	if recoverySourcePhysicallyFenced(
		facts,
	) {
		t.Fatal(
			"execution mismatch must invalidate fence proof",
		)
	}
}

func TestRecoverySourcePhysicalFenceRejectsActiveLease(
	t *testing.T,
) {
	facts := fencedFacts()

	facts.LeaseState =
		"active"

	if recoverySourcePhysicallyFenced(
		facts,
	) {
		t.Fatal(
			"active lease is not physical fencing proof",
		)
	}
}

func TestRecoveryTargetUsesLiveReleaseAfterFence(
	t *testing.T,
) {
	facts := fencedFacts()

	target :=
		recoveryAttemptTargetForFacts(
			facts,
		)

	if target.ID != "live-release" ||
		target.Version != "26.7.28" {

		t.Fatalf(
			"target=%+v want live 26.7.28",
			target,
		)
	}
}

func TestRecoveryTargetUsesSourceReleaseAfterRollback(
	t *testing.T,
) {
	facts :=
		recoveryAttemptFacts{
			SourceStatus:    "rolled_back",
			SourceReleaseID: "source-release",
			ReleaseType:     "xray",
			ReleaseVersion:  "26.7.28",
			ReleaseChannel:  "canary",
		}

	target :=
		recoveryAttemptTargetForFacts(
			facts,
		)

	if target.ID != "source-release" ||
		target.Version != "26.7.28" {

		t.Fatalf(
			"target=%+v want source release",
			target,
		)
	}
}
