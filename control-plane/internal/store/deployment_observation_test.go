package store

import (
	"testing"
	"time"
)

func TestDeploymentOperationalState(
	t *testing.T,
) {
	tests := []struct {
		name       string
		status     string
		age        time.Duration
		wantState  string
		wantStuck  bool
		wantReason string
	}{
		{
			name:      "pending fresh",
			status:    "pending",
			age:       9*time.Minute + 59*time.Second,
			wantState: "pending",
		},
		{
			name:       "pending timeout boundary",
			status:     "pending",
			age:        10 * time.Minute,
			wantState:  "stuck_pending",
			wantStuck:  true,
			wantReason: "deployment_timeout",
		},
		{
			name:      "applying fresh",
			status:    "applying",
			age:       14*time.Minute + 59*time.Second,
			wantState: "applying",
		},
		{
			name:       "applying timeout boundary",
			status:     "applying",
			age:        15 * time.Minute,
			wantState:  "stuck_applying",
			wantStuck:  true,
			wantReason: "deployment_timeout",
		},
		{
			name:      "healthy terminal",
			status:    "healthy",
			age:       100 * time.Hour,
			wantState: "terminal",
		},
		{
			name:      "failed terminal",
			status:    "failed",
			age:       100 * time.Hour,
			wantState: "terminal",
		},
		{
			name:      "rollback terminal",
			status:    "rolled_back",
			age:       100 * time.Hour,
			wantState: "terminal",
		},
		{
			name:      "negative clock skew",
			status:    "pending",
			age:       -30 * time.Second,
			wantState: "pending",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				state, stuck, reason :=
					deploymentOperationalState(
						tt.status,
						tt.age,
					)

				if state != tt.wantState {
					t.Fatalf(
						"state=%q want=%q",
						state,
						tt.wantState,
					)
				}

				if stuck != tt.wantStuck {
					t.Fatalf(
						"stuck=%v want=%v",
						stuck,
						tt.wantStuck,
					)
				}

				if reason != tt.wantReason {
					t.Fatalf(
						"reason=%q want=%q",
						reason,
						tt.wantReason,
					)
				}
			},
		)
	}
}
