package store

import (
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func TestCoreReleaseAllowedByPolicy(
	t *testing.T,
) {
	tests := []struct {
		name          string
		policy        string
		pinnedVersion string
		version       string
		channel       string
		want          bool
	}{
		{
			name:          "pinned matching version",
			policy:        "pinned",
			pinnedVersion: "26.7.28",
			version:       "26.7.28",
			channel:       "canary",
			want:          true,
		},
		{
			name:          "pinned different version",
			policy:        "pinned",
			pinnedVersion: "26.7.28",
			version:       "26.7.11",
			channel:       "testing",
			want:          false,
		},
		{
			name:    "testing accepts testing",
			policy:  "testing",
			version: "26.7.11",
			channel: "testing",
			want:    true,
		},
		{
			name:    "testing accepts canary",
			policy:  "testing",
			version: "26.7.28",
			channel: "canary",
			want:    true,
		},
		{
			name:    "testing accepts stable",
			policy:  "testing",
			version: "26.7.28",
			channel: "stable",
			want:    true,
		},
		{
			name:    "canary rejects testing",
			policy:  "canary",
			version: "26.7.11",
			channel: "testing",
			want:    false,
		},
		{
			name:    "canary accepts canary",
			policy:  "canary",
			version: "26.7.28",
			channel: "canary",
			want:    true,
		},
		{
			name:    "canary accepts stable",
			policy:  "canary",
			version: "26.7.28",
			channel: "stable",
			want:    true,
		},
		{
			name:    "stable rejects canary",
			policy:  "stable",
			version: "26.7.28",
			channel: "canary",
			want:    false,
		},
		{
			name:    "stable accepts stable",
			policy:  "stable",
			version: "26.7.28",
			channel: "stable",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				got :=
					coreReleaseAllowedByPolicy(
						tt.policy,
						tt.pinnedVersion,
						tt.version,
						tt.channel,
					)

				if got != tt.want {
					t.Fatalf(
						"got %v, want %v",
						got,
						tt.want,
					)
				}
			},
		)
	}
}

func TestCompareCoreVersions(
	t *testing.T,
) {
	tests := []struct {
		left  string
		right string
		want  int
	}{
		{"26.7.28", "26.7.11", 1},
		{"26.7.11", "26.7.28", -1},
		{"26.7.28", "26.7.28", 0},
		{"26.10.1", "26.9.99", 1},
		{"v26.7.28", "26.7.28", 0},
		{"26.7", "26.7.0", 0},
	}

	for _, tt := range tests {
		got :=
			compareCoreVersions(
				tt.left,
				tt.right,
			)

		if got != tt.want {
			t.Fatalf(
				"compareCoreVersions(%q,%q)=%d want %d",
				tt.left,
				tt.right,
				got,
				tt.want,
			)
		}
	}
}

func TestAppendUniqueString(
	t *testing.T,
) {
	values := []string{
		"unapproved",
	}

	values =
		appendUniqueString(
			values,
			"unapproved",
		)

	if len(values) != 1 {
		t.Fatalf(
			"expected duplicate blocker to be ignored, got %v",
			values,
		)
	}

	values =
		appendUniqueString(
			values,
			"wrong_channel",
		)

	if len(values) != 2 {
		t.Fatalf(
			"expected second blocker, got %v",
			values,
		)
	}
}

func TestFinalizeCoreUpdateEvaluation(
	t *testing.T,
) {
	eligible :=
		finalizeCoreUpdateEvaluation(
			model.CoreUpdateEvaluation{
				Blockers: []string{},
			},
		)

	if !eligible.Eligible {
		t.Fatal(
			"expected evaluation without blockers to be eligible",
		)
	}

	blocked :=
		finalizeCoreUpdateEvaluation(
			model.CoreUpdateEvaluation{
				Blockers: []string{
					"unapproved",
				},
			},
		)

	if blocked.Eligible {
		t.Fatal(
			"expected evaluation with blocker to be ineligible",
		)
	}
}

func TestRolloutPlanExpired(
	t *testing.T,
) {
	now :=
		time.Date(
			2026,
			time.August,
			25,
			12,
			0,
			0,
			0,
			time.UTC,
		)

	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name: "future",
			expiresAt: now.Add(
				time.Minute,
			),
			want: false,
		},
		{
			name:      "exactly now",
			expiresAt: now,
			want:      true,
		},
		{
			name: "past",
			expiresAt: now.Add(
				-time.Minute,
			),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name,
			func(t *testing.T) {
				got :=
					rolloutPlanExpired(
						model.RolloutPlan{
							ExpiresAt: tt.expiresAt,
						},
						now,
					)

				if got != tt.want {
					t.Fatalf(
						"got %v, want %v",
						got,
						tt.want,
					)
				}
			},
		)
	}
}
