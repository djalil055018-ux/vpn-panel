package recovery

import (
	"time"

	"vpn-platform/internal/model"
)

const (
	ActionNone               = "none"
	ActionWait               = "wait"
	ActionRetryReconcile     = "retry_reconcile"
	ActionManualIntervention = "manual_intervention"
)

func Evaluate(
	facts model.RecoveryFacts,
	evaluatedAt time.Time,
) model.RecoveryEvaluation {
	result :=
		model.RecoveryEvaluation{
			DeploymentID:            facts.DeploymentID,
			NodeID:                  facts.NodeID,
			Generation:              facts.Generation,
			DeploymentStatus:        facts.Status,
			OperationalState:        facts.OperationalState,
			Stuck:                   facts.Stuck,
			ExecutionID:             facts.ExecutionID,
			ExecutionEpoch:          facts.ExecutionEpoch,
			LeaseState:              facts.LeaseState,
			FenceState:              facts.FenceState,
			PhysicalFenceProven:     facts.PhysicalFenceProven,
			DesiredGeneration:       facts.DesiredGeneration,
			AppliedGeneration:       facts.AppliedGeneration,
			NodeOnline:              facts.NodeOnline,
			HealthFresh:             facts.HealthFresh,
			NodeHealthy:             facts.NodeHealthy,
			HealthAppliedGeneration: facts.HealthAppliedGeneration,
			RequestedCoreVersion:    facts.RequestedCoreVersion,
			AppliedCoreVersion:      facts.AppliedCoreVersion,
			CurrentCoreVersion:      facts.CurrentCoreVersion,
			RecommendedAction:       ActionNone,
			AutomaticAllowed:        false,
			Blockers:                make([]string, 0),
			EvaluatedAt:             evaluatedAt,
		}

	addBlocker :=
		func(value string) {
			result.Blockers =
				append(
					result.Blockers,
					value,
				)
		}

	if facts.Status == "healthy" {
		addBlocker(
			"deployment_healthy",
		)
		return result
	}

	if facts.Generation <=
		facts.AppliedGeneration ||
		facts.Generation <
			facts.DesiredGeneration {

		addBlocker(
			"deployment_superseded",
		)
		return result
	}

	if facts.Generation >
		facts.DesiredGeneration {

		result.RecoveryNeeded = true
		result.RecommendedAction =
			ActionManualIntervention

		addBlocker(
			"generation_ahead_of_desired_state",
		)

		return result
	}

	result.RecoveryNeeded = true

	if !facts.NodeOnline {
		result.RecommendedAction =
			ActionWait

		addBlocker(
			"node_offline",
		)

		return result
	}

	if !facts.HealthFresh {
		result.RecommendedAction =
			ActionWait

		addBlocker(
			"node_health_stale",
		)

		return result
	}

	switch facts.Status {
	case "rolled_back":
		if !facts.NodeHealthy {
			result.RecommendedAction =
				ActionManualIntervention

			addBlocker(
				"rollback_health_not_confirmed",
			)

			return result
		}

		if facts.HealthAppliedGeneration !=
			facts.AppliedGeneration {

			result.RecommendedAction =
				ActionManualIntervention

			addBlocker(
				"health_generation_mismatch",
			)

			return result
		}

		result.RecommendedAction =
			ActionRetryReconcile

		result.AutomaticAllowed = true

		return result

	case "failed":
		result.RecommendedAction =
			ActionManualIntervention

		addBlocker(
			"deployment_failed_without_healthy_rollback",
		)

		return result

	case "pending",
		"applying":

		if facts.PhysicalFenceProven {
			if !facts.NodeHealthy {
				result.RecommendedAction =
					ActionManualIntervention

				addBlocker(
					"fenced_source_health_not_confirmed",
				)

				return result
			}

			if facts.HealthAppliedGeneration !=
				facts.AppliedGeneration {

				result.RecommendedAction =
					ActionManualIntervention

				addBlocker(
					"health_generation_mismatch",
				)

				return result
			}

			if facts.CurrentCoreVersion == "" {
				result.RecommendedAction =
					ActionManualIntervention

				addBlocker(
					"fenced_source_core_missing",
				)

				return result
			}

			result.RecommendedAction =
				ActionRetryReconcile

			result.AutomaticAllowed = true

			return result
		}

		if !facts.Stuck {
			result.RecommendedAction =
				ActionWait

			addBlocker(
				"deployment_not_stuck",
			)

			return result
		}

		result.RecommendedAction =
			ActionManualIntervention

		addBlocker(
			"stuck_attempt_requires_fencing",
		)

		return result

	default:
		result.RecommendedAction =
			ActionManualIntervention

		addBlocker(
			"unknown_deployment_status",
		)

		return result
	}
}
