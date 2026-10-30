package model

import "time"

type NodeLifecycleStatus struct {
	RuntimeCore                string     `json:"runtime_core"`
	NodeID                     string     `json:"node_id"`
	State                      string     `json:"state"`
	Online                     bool       `json:"online"`
	Registered                 bool       `json:"registered"`
	BootstrapConsumed          bool       `json:"bootstrap_consumed"`
	AgentVersion               string     `json:"agent_version,omitempty"`
	OSName                     string     `json:"os_name,omitempty"`
	OSVersion                  string     `json:"os_version,omitempty"`
	Architecture               string     `json:"architecture,omitempty"`
	DesiredGeneration          int64      `json:"desired_generation"`
	AppliedGeneration          int64      `json:"applied_generation"`
	GenerationDrift            int64      `json:"generation_drift"`
	HealthPresent              bool       `json:"health_present"`
	HealthFresh                bool       `json:"health_fresh"`
	Healthy                    bool       `json:"healthy"`
	CurrentCoreVersion         string     `json:"current_core_version,omitempty"`
	LastKnownGoodCoreVersion   string     `json:"last_known_good_core_version,omitempty"`
	RollbackReady              bool       `json:"rollback_ready"`
	LatestDeploymentGeneration int64      `json:"latest_deployment_generation,omitempty"`
	LatestDeploymentStatus     string     `json:"latest_deployment_status,omitempty"`
	ActiveRecovery             bool       `json:"active_recovery"`
	LastSeenAt                 *time.Time `json:"last_seen_at,omitempty"`
	HealthCheckedAt            *time.Time `json:"health_checked_at,omitempty"`
}

type NodeDetail struct {
	Node      Node                `json:"node"`
	Runtime   NodeRuntimeStatus   `json:"runtime"`
	Lifecycle NodeLifecycleStatus `json:"lifecycle"`
}

type DiagnosticCheck struct {
	Code    string `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type NodeDiagnostics struct {
	NodeID         string            `json:"node_id"`
	LifecycleState string            `json:"lifecycle_state"`
	Overall        string            `json:"overall"`
	Checks         []DiagnosticCheck `json:"checks"`
	GeneratedAt    time.Time         `json:"generated_at"`
}
