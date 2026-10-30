package recovery

import (
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func TestEvaluateRecovery(
	t *testing.T,
) {
	now :=
		time.Date(
			2026,
			8,
			28,
			0,
			0,
			0,
			0,
			time.UTC,
		)

	tests := []struct {
		name             string
		facts            model.RecoveryFacts
		wantAction       string
		wantRecovery     bool
		wantAutomatic    bool
		wantFirstBlocker string
	}{
		{
			name: "healthy needs nothing",
			facts: model.RecoveryFacts{
				Status:            "healthy",
				Generation:        17,
				DesiredGeneration: 17,
				AppliedGeneration: 17,
			},
			wantAction:       ActionNone,
			wantFirstBlocker: "deployment_healthy",
		},
		{
			name: "historical rollback is superseded",
			facts: model.RecoveryFacts{
				Status:            "rolled_back",
				Generation:        16,
				DesiredGeneration: 17,
				AppliedGeneration: 15,
			},
			wantAction:       ActionNone,
			wantFirstBlocker: "deployment_superseded",
		},
		{
			name: "current healthy rollback may recover",
			facts: model.RecoveryFacts{
				Status:                  "rolled_back",
				Generation:              17,
				DesiredGeneration:       17,
				AppliedGeneration:       16,
				NodeOnline:              true,
				HealthFresh:             true,
				NodeHealthy:             true,
				HealthAppliedGeneration: 16,
				CurrentCoreVersion:      "26.7.28",
			},
			wantAction:    ActionRetryReconcile,
			wantRecovery:  true,
			wantAutomatic: true,
		},
		{
			name: "offline node waits",
			facts: model.RecoveryFacts{
				Status:            "rolled_back",
				Generation:        17,
				DesiredGeneration: 17,
				AppliedGeneration: 16,
				NodeOnline:        false,
			},
			wantAction:       ActionWait,
			wantRecovery:     true,
			wantFirstBlocker: "node_offline",
		},
		{
			name: "failed needs manual intervention",
			facts: model.RecoveryFacts{
				Status:            "failed",
				Generation:        17,
				DesiredGeneration: 17,
				AppliedGeneration: 16,
				NodeOnline:        true,
				HealthFresh:       true,
			},
			wantAction:       ActionManualIntervention,
			wantRecovery:     true,
			wantFirstBlocker: "deployment_failed_without_healthy_rollback",
		},
		{
			name: "stuck applying without proof needs fencing",
			facts: model.RecoveryFacts{
				Status:            "applying",
				Stuck:             true,
				Generation:        17,
				DesiredGeneration: 17,
				AppliedGeneration: 15,
				NodeOnline:        true,
				HealthFresh:       true,
				NodeHealthy:       true,
			},
			wantAction:       ActionManualIntervention,
			wantRecovery:     true,
			wantFirstBlocker: "stuck_attempt_requires_fencing",
		},
		{
			name: "fresh applying without proof waits",
			facts: model.RecoveryFacts{
				Status:            "applying",
				Stuck:             false,
				Generation:        17,
				DesiredGeneration: 17,
				AppliedGeneration: 15,
				NodeOnline:        true,
				HealthFresh:       true,
				NodeHealthy:       true,
			},
			wantAction:       ActionWait,
			wantRecovery:     true,
			wantFirstBlocker: "deployment_not_stuck",
		},
		{
			name: "physically fenced applying may recover immediately",
			facts: model.RecoveryFacts{
				Status:                  "applying",
				Stuck:                   false,
				Generation:              17,
				DesiredGeneration:       17,
				AppliedGeneration:       15,
				NodeOnline:              true,
				HealthFresh:             true,
				NodeHealthy:             true,
				HealthAppliedGeneration: 15,
				CurrentCoreVersion:      "26.7.28",
				LeaseState:              "fenced",
				FenceState:              "acknowledged",
				PhysicalFenceProven:     true,
			},
			wantAction:    ActionRetryReconcile,
			wantRecovery:  true,
			wantAutomatic: true,
		},
		{
			name: "physically fenced source still needs healthy data plane",
			facts: model.RecoveryFacts{
				Status:                  "applying",
				Generation:              17,
				DesiredGeneration:       17,
				AppliedGeneration:       15,
				NodeOnline:              true,
				HealthFresh:             true,
				NodeHealthy:             false,
				HealthAppliedGeneration: 15,
				CurrentCoreVersion:      "26.7.28",
				PhysicalFenceProven:     true,
			},
			wantAction:       ActionManualIntervention,
			wantRecovery:     true,
			wantFirstBlocker: "fenced_source_health_not_confirmed",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				got :=
					Evaluate(
						tt.facts,
						now,
					)

				if got.RecommendedAction !=
					tt.wantAction {

					t.Fatalf(
						"action=%q want=%q",
						got.RecommendedAction,
						tt.wantAction,
					)
				}

				if got.RecoveryNeeded !=
					tt.wantRecovery {

					t.Fatalf(
						"recovery_needed=%v want=%v",
						got.RecoveryNeeded,
						tt.wantRecovery,
					)
				}

				if got.AutomaticAllowed !=
					tt.wantAutomatic {

					t.Fatalf(
						"automatic_allowed=%v want=%v",
						got.AutomaticAllowed,
						tt.wantAutomatic,
					)
				}

				if tt.wantFirstBlocker != "" {
					if len(got.Blockers) == 0 ||
						got.Blockers[0] !=
							tt.wantFirstBlocker {

						t.Fatalf(
							"blockers=%v want first=%q",
							got.Blockers,
							tt.wantFirstBlocker,
						)
					}
				}
			},
		)
	}
}
