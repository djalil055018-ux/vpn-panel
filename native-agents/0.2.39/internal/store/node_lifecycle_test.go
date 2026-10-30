package store

import (
	"testing"
	"time"

	"vpn-platform/internal/model"
)

func lifecycleTestFacts(
	now time.Time,
) nodeLifecycleFacts {
	lastSeen := now
	healthChecked := now

	return nodeLifecycleFacts{
		Node: model.Node{
			ID:                "node",
			AgentVersion:      "0.2.12",
			DesiredGeneration: 18,
			AppliedGeneration: 18,
			LastSeenAt:        &lastSeen,
		},

		Registered:        true,
		BootstrapConsumed: true,

		HealthPresent:   true,
		HealthHealthy:   true,
		HealthCheckedAt: &healthChecked,

		HealthCoreVersion: "26.7.28",

		HealthLKGVersion: "26.7.28",

		RollbackReady: true,

		LatestDeploymentGeneration: 18,

		LatestDeploymentStatus: "healthy",
	}
}

func TestDeriveNodeLifecycleOnline(
	t *testing.T,
) {
	now := time.Now().UTC()

	got :=
		deriveNodeLifecycle(
			lifecycleTestFacts(now),
			now,
		)

	if got.State != "online" {
		t.Fatalf(
			"state=%q want=online",
			got.State,
		)
	}
}

func TestDeriveNodeLifecycleProvisioning(
	t *testing.T,
) {
	now := time.Now().UTC()
	facts := lifecycleTestFacts(now)

	facts.Registered = false

	got :=
		deriveNodeLifecycle(
			facts,
			now,
		)

	if got.State != "provisioning" {
		t.Fatalf(
			"state=%q want=provisioning",
			got.State,
		)
	}
}

func TestDeriveNodeLifecycleOffline(
	t *testing.T,
) {
	now := time.Now().UTC()
	facts := lifecycleTestFacts(now)

	stale :=
		now.Add(
			-nodeOnlineWindow -
				time.Second,
		)

	facts.Node.LastSeenAt = &stale

	got :=
		deriveNodeLifecycle(
			facts,
			now,
		)

	if got.State != "offline" {
		t.Fatalf(
			"state=%q want=offline",
			got.State,
		)
	}
}

func TestDeriveNodeLifecycleRecoveringPrecedesUpdating(
	t *testing.T,
) {
	now := time.Now().UTC()
	facts := lifecycleTestFacts(now)

	facts.ActiveRecovery = true
	facts.Node.DesiredGeneration = 19

	got :=
		deriveNodeLifecycle(
			facts,
			now,
		)

	if got.State != "recovering" {
		t.Fatalf(
			"state=%q want=recovering",
			got.State,
		)
	}
}

func TestDeriveNodeLifecycleUpdating(
	t *testing.T,
) {
	now := time.Now().UTC()
	facts := lifecycleTestFacts(now)

	facts.Node.DesiredGeneration = 19

	got :=
		deriveNodeLifecycle(
			facts,
			now,
		)

	if got.State != "updating" {
		t.Fatalf(
			"state=%q want=updating",
			got.State,
		)
	}
}

func TestDeriveNodeLifecycleDegraded(
	t *testing.T,
) {
	now := time.Now().UTC()
	facts := lifecycleTestFacts(now)

	facts.HealthHealthy = false

	got :=
		deriveNodeLifecycle(
			facts,
			now,
		)

	if got.State != "degraded" {
		t.Fatalf(
			"state=%q want=degraded",
			got.State,
		)
	}
}
