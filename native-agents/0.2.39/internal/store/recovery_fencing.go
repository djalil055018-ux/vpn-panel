package store

type recoveryAttemptTarget struct {
	ID      string
	Type    string
	Version string
	Channel string
}

func recoverySourcePhysicallyFenced(
	facts recoveryAttemptFacts,
) bool {
	if facts.SourceStatus != "pending" &&
		facts.SourceStatus != "applying" {
		return false
	}

	if facts.SourceExecutionID == "" ||
		facts.SourceExecutionEpoch < 1 {
		return false
	}

	if facts.LeaseState != "fenced" ||
		facts.LeaseExecutionID !=
			facts.SourceExecutionID ||
		facts.LeaseExecutionEpoch !=
			facts.SourceExecutionEpoch ||
		facts.LeaseOwnerInstanceID == "" {
		return false
	}

	if facts.FenceState != "acknowledged" ||
		facts.FenceExecutionID !=
			facts.SourceExecutionID ||
		facts.FenceExecutionEpoch !=
			facts.SourceExecutionEpoch {
		return false
	}

	if facts.FenceTargetOwnerInstanceID !=
		facts.LeaseOwnerInstanceID {
		return false
	}

	if facts.FenceAcknowledgedByInstanceID !=
		facts.LeaseOwnerInstanceID {
		return false
	}

	return true
}

func recoveryAttemptTargetForFacts(
	facts recoveryAttemptFacts,
) recoveryAttemptTarget {
	switch facts.SourceStatus {
	case "rolled_back":
		return recoveryAttemptTarget{
			ID:      facts.SourceReleaseID,
			Type:    facts.ReleaseType,
			Version: facts.ReleaseVersion,
			Channel: facts.ReleaseChannel,
		}

	case "pending",
		"applying":

		if !recoverySourcePhysicallyFenced(
			facts,
		) {
			return recoveryAttemptTarget{}
		}

		return recoveryAttemptTarget{
			ID:      facts.LiveReleaseID,
			Type:    facts.LiveReleaseType,
			Version: facts.LiveReleaseVersion,
			Channel: facts.LiveReleaseChannel,
		}

	default:
		return recoveryAttemptTarget{}
	}
}
