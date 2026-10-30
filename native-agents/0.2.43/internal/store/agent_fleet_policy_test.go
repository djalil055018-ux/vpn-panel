package store

import "testing"

func TestAgentFleetRouterNamesAreExcludedFromAutomaticUpdates(t *testing.T) {
	cases := []struct {
		name     string
		eligible bool
	}{
		{name: "Sweden", eligible: true},
		{name: "Финляндия 2", eligible: true},
		{name: "🇫🇮 Finland Router", eligible: false},
		{name: "Россия Роутер", eligible: false},
		{name: "router-lab", eligible: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentFleetNodeNameEligible(tc.name); got != tc.eligible {
				t.Fatalf("agentFleetNodeNameEligible(%q)=%v, want %v", tc.name, got, tc.eligible)
			}
		})
	}
}
