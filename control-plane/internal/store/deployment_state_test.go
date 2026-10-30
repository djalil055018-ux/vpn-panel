package store

import "testing"

func TestDeploymentTransition(
	t *testing.T,
) {
	tests := []struct {
		name        string
		current     string
		next        string
		wantChanged bool
		wantAllowed bool
	}{
		{
			name:        "pending applying",
			current:     "pending",
			next:        "applying",
			wantChanged: true,
			wantAllowed: true,
		},
		{
			name:        "pending healthy",
			current:     "pending",
			next:        "healthy",
			wantChanged: true,
			wantAllowed: true,
		},
		{
			name:        "pending failed",
			current:     "pending",
			next:        "failed",
			wantChanged: true,
			wantAllowed: true,
		},
		{
			name:        "pending rolled back",
			current:     "pending",
			next:        "rolled_back",
			wantChanged: true,
			wantAllowed: true,
		},
		{
			name:        "applying healthy",
			current:     "applying",
			next:        "healthy",
			wantChanged: true,
			wantAllowed: true,
		},
		{
			name:        "applying failed",
			current:     "applying",
			next:        "failed",
			wantChanged: true,
			wantAllowed: true,
		},
		{
			name:        "applying rolled back",
			current:     "applying",
			next:        "rolled_back",
			wantChanged: true,
			wantAllowed: true,
		},
		{
			name:        "repeat applying",
			current:     "applying",
			next:        "applying",
			wantChanged: false,
			wantAllowed: true,
		},
		{
			name:        "repeat healthy",
			current:     "healthy",
			next:        "healthy",
			wantChanged: false,
			wantAllowed: true,
		},
		{
			name:        "repeat failed",
			current:     "failed",
			next:        "failed",
			wantChanged: false,
			wantAllowed: true,
		},
		{
			name:        "repeat rollback",
			current:     "rolled_back",
			next:        "rolled_back",
			wantChanged: false,
			wantAllowed: true,
		},
		{
			name:        "healthy applying blocked",
			current:     "healthy",
			next:        "applying",
			wantChanged: false,
			wantAllowed: false,
		},
		{
			name:        "healthy failed blocked",
			current:     "healthy",
			next:        "failed",
			wantChanged: false,
			wantAllowed: false,
		},
		{
			name:        "failed healthy blocked",
			current:     "failed",
			next:        "healthy",
			wantChanged: false,
			wantAllowed: false,
		},
		{
			name:        "rollback healthy blocked",
			current:     "rolled_back",
			next:        "healthy",
			wantChanged: false,
			wantAllowed: false,
		},
		{
			name:        "applying pending blocked",
			current:     "applying",
			next:        "pending",
			wantChanged: false,
			wantAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				changed, allowed :=
					deploymentTransition(
						tt.current,
						tt.next,
					)

				if changed != tt.wantChanged {
					t.Fatalf(
						"changed=%v want=%v",
						changed,
						tt.wantChanged,
					)
				}

				if allowed != tt.wantAllowed {
					t.Fatalf(
						"allowed=%v want=%v",
						allowed,
						tt.wantAllowed,
					)
				}
			},
		)
	}
}
