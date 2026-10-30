package main

import "testing"

func TestGenerationAwaitingRecovery(
	t *testing.T,
) {
	tests := []struct {
		name    string
		desired int64
		applied int64
		failed  int64
		want    bool
	}{
		{
			name:    "failed current desired generation is terminal",
			desired: 15,
			applied: 14,
			failed:  15,
			want:    true,
		},
		{
			name:    "new generation after failure may execute",
			desired: 16,
			applied: 14,
			failed:  15,
			want:    false,
		},
		{
			name:    "normal unapplied generation may execute",
			desired: 15,
			applied: 14,
			failed:  0,
			want:    false,
		},
		{
			name:    "already applied generation needs no recovery",
			desired: 14,
			applied: 14,
			failed:  14,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				got :=
					generationAwaitingRecovery(
						tt.desired,
						tt.applied,
						tt.failed,
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
