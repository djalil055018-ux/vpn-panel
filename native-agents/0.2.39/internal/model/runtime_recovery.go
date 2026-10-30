package model

import "time"

type RuntimeRecoveryInfo struct {
	CurrentCoreVersion       string `json:"current_core_version,omitempty"`
	LastKnownGoodCoreVersion string `json:"last_known_good_core_version,omitempty"`
	SnapshotCount            int64  `json:"snapshot_count"`
	LatestSnapshotID         string `json:"latest_snapshot_id,omitempty"`
	RollbackReady            bool   `json:"rollback_ready"`
}

type NodeRuntimeStatus struct {
	NodeID                   string     `json:"node_id"`
	NodeStatus               string     `json:"node_status"`
	HealthPresent            bool       `json:"health_present"`
	Healthy                  bool       `json:"healthy"`
	DesiredGeneration        int64      `json:"desired_generation"`
	AppliedGeneration        int64      `json:"applied_generation"`
	HealthAppliedGeneration  int64      `json:"health_applied_generation"`
	CurrentCoreVersion       string     `json:"current_core_version,omitempty"`
	LastKnownGoodCoreVersion string     `json:"last_known_good_core_version,omitempty"`
	SnapshotCount            int64      `json:"snapshot_count"`
	LatestSnapshotID         string     `json:"latest_snapshot_id,omitempty"`
	RollbackReady            bool       `json:"rollback_ready"`
	CheckedAt                *time.Time `json:"checked_at,omitempty"`
}
