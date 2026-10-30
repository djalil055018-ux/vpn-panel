package store

import (
	"testing"

	"vpn-platform/internal/model"
)

func TestDeploymentReportHasAnyLeaseProof(
	t *testing.T,
) {
	if deploymentReportHasAnyLeaseProof(
		model.DeploymentReport{},
	) {
		t.Fatal(
			"empty report unexpectedly has lease proof",
		)
	}

	if !deploymentReportHasAnyLeaseProof(
		model.DeploymentReport{
			OwnerInstanceID: "owner",
		},
	) {
		t.Fatal(
			"owner proof not detected",
		)
	}

	if !deploymentReportHasAnyLeaseProof(
		model.DeploymentReport{
			LeaseToken: "token",
		},
	) {
		t.Fatal(
			"token proof not detected",
		)
	}
}

func TestCompletedLeaseReportAllowed(
	t *testing.T,
) {
	tests := []struct {
		name         string
		leaseState   string
		reportStatus string
		changed      bool
		want         bool
	}{
		{
			name:         "terminal idempotent retry",
			leaseState:   "completed",
			reportStatus: "healthy",
			changed:      false,
			want:         true,
		},
		{
			name:         "completed cannot authorize applying",
			leaseState:   "completed",
			reportStatus: "applying",
			changed:      false,
			want:         false,
		},
		{
			name:         "completed cannot authorize transition",
			leaseState:   "completed",
			reportStatus: "healthy",
			changed:      true,
			want:         false,
		},
		{
			name:         "active lease unaffected",
			leaseState:   "active",
			reportStatus: "applying",
			changed:      true,
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				got :=
					completedLeaseReportAllowed(
						tt.leaseState,
						tt.reportStatus,
						tt.changed,
					)

				if got != tt.want {
					t.Fatalf(
						"got=%v want=%v",
						got,
						tt.want,
					)
				}
			},
		)
	}
}
