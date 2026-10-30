package model

import "time"

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Node struct {
	RuntimeCore       string     `json:"runtime_core"`
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	Name              string     `json:"name"`
	Status            string     `json:"status"`
	AgentVersion      string     `json:"agent_version,omitempty"`
	OSName            string     `json:"os_name,omitempty"`
	OSVersion         string     `json:"os_version,omitempty"`
	Architecture      string     `json:"architecture,omitempty"`
	DesiredGeneration int64      `json:"desired_generation"`
	AppliedGeneration int64      `json:"applied_generation"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

type CoreRelease struct {
	Type        string `json:"type"`
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
	Channel     string `json:"channel,omitempty"`
}

type ClientSpec struct {
	PPTP      *PPTPPeer      `json:"pptp,omitempty"`
	WireGuard *WireGuardPeer `json:"wireguard,omitempty"`
	ID        string         `json:"id"`
	StatsKey  string         `json:"stats_key,omitempty"`
}

type ServiceSpec struct {
	OpenVPN     *OpenVPNSpec     `json:"openvpn,omitempty"`
	WireGuard   *WireGuardSpec   `json:"wireguard,omitempty"`
	Shadowsocks *ShadowsocksSpec `json:"shadowsocks,omitempty"`
	ID          string           `json:"id"`
	Protocol    string           `json:"protocol"`
	Listen      string           `json:"listen"`
	Port        int              `json:"port"`
	Transport   string           `json:"transport"`
	Security    string           `json:"security"`
	Clients     []ClientSpec     `json:"clients,omitempty"`
	Reality     *RealitySpec     `json:"reality,omitempty"`
	TLS         *TLSSpec         `json:"tls,omitempty"`
}

// Only the certificate identity is distributed. File paths are resolved locally
// by the agent and cannot be supplied through the Control Plane API.
type TLSSpec struct {
	CertificateID   string `json:"certificate_id"`
	ServerName      string `json:"server_name"`
	CertificateFile string `json:"-"`
	KeyFile         string `json:"-"`
}

type DesiredState struct {
	Generation   int64             `json:"generation"`
	Core         CoreRelease       `json:"core"`
	Services     []ServiceSpec     `json:"services"`
	XrayProfile  *XrayProfileSpec  `json:"xray_profile,omitempty"`
	XrayCascades *XrayCascadesSpec `json:"xray_cascades,omitempty"`
}

type ExecutionAssignment struct {
	DeploymentID   string `json:"deployment_id"`
	Generation     int64  `json:"generation"`
	ExecutionID    string `json:"execution_id"`
	ExecutionEpoch int64  `json:"execution_epoch"`
}

type AgentAssignment struct {
	DesiredState DesiredState        `json:"desired_state"`
	Execution    ExecutionAssignment `json:"execution"`

	DeploymentStatus      string `json:"deployment_status"`
	NodeAppliedGeneration int64  `json:"node_applied_generation"`
	AppliedCoreVersion    string `json:"applied_core_version,omitempty"`

	FenceRequest *ExecutionFenceRequest `json:"fence_request,omitempty"`
}

type HealthReport struct {
	RuntimeRecoveryInfo
	Healthy           bool      `json:"healthy"`
	AppliedGeneration int64     `json:"applied_generation"`
	Core              string    `json:"core"`
	CoreVersion       string    `json:"core_version"`
	Message           string    `json:"message"`
	CheckedAt         time.Time `json:"checked_at"`

	AgentVersion    string                 `json:"agent_version,omitempty"`
	OSName          string                 `json:"os_name,omitempty"`
	OSVersion       string                 `json:"os_version,omitempty"`
	Architecture    string                 `json:"architecture,omitempty"`
	Metrics         *NodeMetrics           `json:"metrics,omitempty"`
	ClientTraffic   []ClientTraffic        `json:"client_traffic,omitempty"`
	TrafficSnapshot *ClientTrafficSnapshot `json:"traffic_snapshot,omitempty"`
}

type DeploymentObservation struct {
	ID                   string     `json:"id"`
	NodeID               string     `json:"node_id"`
	Generation           int64      `json:"generation"`
	Status               string     `json:"status"`
	PreviousCoreVersion  string     `json:"previous_core_version,omitempty"`
	RequestedCoreVersion string     `json:"requested_core_version,omitempty"`
	AppliedCoreVersion   string     `json:"applied_core_version,omitempty"`
	ErrorMessage         string     `json:"error_message,omitempty"`
	CoreReleaseID        string     `json:"core_release_id,omitempty"`
	CoreType             string     `json:"core_type,omitempty"`
	StartedAt            time.Time  `json:"started_at"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
	UpdatedAt            time.Time  `json:"updated_at"`

	OperationalState string `json:"operational_state"`
	Stuck            bool   `json:"stuck"`
	StuckReason      string `json:"stuck_reason,omitempty"`
	AgeSeconds       int64  `json:"age_seconds"`
	NodeOnline       bool   `json:"node_online"`
}

type RecoveryFacts struct {
	DeploymentID     string
	NodeID           string
	Generation       int64
	Status           string
	OperationalState string
	Stuck            bool

	ExecutionID    string
	ExecutionEpoch int64

	LeaseState          string
	FenceState          string
	PhysicalFenceProven bool

	RequestedCoreVersion string
	AppliedCoreVersion   string
	DeploymentUpdatedAt  time.Time

	DesiredGeneration int64
	AppliedGeneration int64
	NodeOnline        bool

	HealthFresh             bool
	NodeHealthy             bool
	HealthAppliedGeneration int64
	CurrentCoreVersion      string
}

type RecoveryEvaluation struct {
	DeploymentID     string `json:"deployment_id"`
	NodeID           string `json:"node_id"`
	Generation       int64  `json:"generation"`
	DeploymentStatus string `json:"deployment_status"`
	OperationalState string `json:"operational_state"`
	Stuck            bool   `json:"stuck"`

	ExecutionID    string `json:"execution_id,omitempty"`
	ExecutionEpoch int64  `json:"execution_epoch,omitempty"`

	LeaseState          string `json:"lease_state,omitempty"`
	FenceState          string `json:"fence_state,omitempty"`
	PhysicalFenceProven bool   `json:"physical_fence_proven"`

	DesiredGeneration int64 `json:"desired_generation"`
	AppliedGeneration int64 `json:"applied_generation"`

	NodeOnline              bool  `json:"node_online"`
	HealthFresh             bool  `json:"health_fresh"`
	NodeHealthy             bool  `json:"node_healthy"`
	HealthAppliedGeneration int64 `json:"health_applied_generation"`

	RequestedCoreVersion string `json:"requested_core_version,omitempty"`
	AppliedCoreVersion   string `json:"applied_core_version,omitempty"`
	CurrentCoreVersion   string `json:"current_core_version,omitempty"`

	RecoveryNeeded    bool     `json:"recovery_needed"`
	RecommendedAction string   `json:"recommended_action"`
	AutomaticAllowed  bool     `json:"automatic_allowed"`
	Blockers          []string `json:"blockers"`

	EvaluatedAt time.Time `json:"evaluated_at"`
}
type RecoveryAttempt struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	NodeID   string `json:"node_id"`

	SourceDeploymentID     string `json:"source_deployment_id"`
	SourceGeneration       int64  `json:"source_generation"`
	SourceDeploymentStatus string `json:"source_deployment_status"`

	BaseDesiredGeneration int64 `json:"base_desired_generation"`
	BaseAppliedGeneration int64 `json:"base_applied_generation"`
	ProposedGeneration    int64 `json:"proposed_generation"`

	CoreType string `json:"core_type"`

	TargetCoreReleaseID string `json:"target_core_release_id,omitempty"`
	TargetVersion       string `json:"target_version,omitempty"`
	TargetChannel       string `json:"target_channel,omitempty"`

	Status   string   `json:"status"`
	Blockers []string `json:"blockers"`

	DesiredStatePreview *DesiredState `json:"desired_state_preview,omitempty"`

	DeploymentID string `json:"deployment_id,omitempty"`

	CreatedBy string `json:"created_by"`

	ApprovedBy string     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`

	ExecutedAt  *time.Time `json:"executed_at,omitempty"`
	CancelledAt *time.Time `json:"cancelled_at,omitempty"`

	FailureReason string `json:"failure_reason,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ExecutionLeaseClaimRequest struct {
	Execution       ExecutionAssignment `json:"execution"`
	OwnerInstanceID string              `json:"owner_instance_id"`
}

type ExecutionLeaseRenewRequest struct {
	Execution       ExecutionAssignment `json:"execution"`
	OwnerInstanceID string              `json:"owner_instance_id"`
	LeaseToken      string              `json:"lease_token"`
}

type ExecutionLeaseGrant struct {
	LeaseToken        string    `json:"lease_token,omitempty"`
	LeaseExpiresAt    time.Time `json:"lease_expires_at"`
	RenewAfterSeconds int64     `json:"renew_after_seconds"`
}

type ExecutionFenceRequest struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	NodeID   string `json:"node_id"`

	DeploymentID   string `json:"deployment_id"`
	Generation     int64  `json:"generation"`
	ExecutionID    string `json:"execution_id"`
	ExecutionEpoch int64  `json:"execution_epoch"`

	State string `json:"state"`

	TargetOwnerInstanceID string `json:"target_owner_instance_id"`

	Reason string `json:"reason"`

	RequestedAt time.Time `json:"requested_at"`

	AcknowledgedAt           *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedByInstanceID string     `json:"acknowledged_by_instance_id,omitempty"`

	CancelledAt *time.Time `json:"cancelled_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ExecutionFenceAckRequest struct {
	FenceRequestID string              `json:"fence_request_id"`
	Execution      ExecutionAssignment `json:"execution"`

	OwnerInstanceID string `json:"owner_instance_id"`

	// RAM-only proof. It is never persisted or logged in raw form.
	FenceProofToken string `json:"fence_proof_token"`
}

type DeploymentReport struct {
	Generation int64 `json:"generation"`

	DeploymentID   string `json:"deployment_id,omitempty"`
	ExecutionID    string `json:"execution_id,omitempty"`
	ExecutionEpoch int64  `json:"execution_epoch,omitempty"`

	OwnerInstanceID string `json:"owner_instance_id,omitempty"`
	LeaseToken      string `json:"lease_token,omitempty"`

	Status             string    `json:"status"`
	AppliedCoreVersion string    `json:"applied_core_version,omitempty"`
	ErrorMessage       string    `json:"error_message,omitempty"`
	ReportedAt         time.Time `json:"reported_at"`
}

type CoreReleaseRecord struct {
	ID                 string    `json:"id"`
	Type               string    `json:"type"`
	Version            string    `json:"version"`
	OS                 string    `json:"os"`
	Architecture       string    `json:"architecture"`
	DownloadURL        string    `json:"download_url"`
	SHA256             string    `json:"sha256"`
	Channel            string    `json:"channel"`
	UpstreamPrerelease bool      `json:"upstream_prerelease"`
	Approved           bool      `json:"approved"`
	Revoked            bool      `json:"revoked"`
	ApprovedBy         string    `json:"approved_by,omitempty"`
	ApprovedAt         string    `json:"approved_at,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type CoreUpdatePolicy struct {
	NodeID        string    `json:"node_id"`
	CoreType      string    `json:"core_type"`
	Policy        string    `json:"policy"`
	PinnedVersion string    `json:"pinned_version,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type CoreUpdateStatus struct {
	NodeID        string `json:"node_id"`
	CoreType      string `json:"core_type"`
	Policy        string `json:"policy"`
	PinnedVersion string `json:"pinned_version,omitempty"`

	CurrentVersion    string `json:"current_version,omitempty"`
	CurrentGeneration int64  `json:"current_generation"`
	CurrentHealthy    bool   `json:"current_healthy"`

	CandidateAvailable bool   `json:"candidate_available"`
	CandidateReleaseID string `json:"candidate_release_id,omitempty"`
	CandidateVersion   string `json:"candidate_version,omitempty"`
	CandidateChannel   string `json:"candidate_channel,omitempty"`

	UpdateAvailable bool `json:"update_available"`
	PolicySatisfied bool `json:"policy_satisfied"`
}

type CoreUpdateEvaluation struct {
	NodeID        string `json:"node_id"`
	CoreType      string `json:"core_type"`
	Version       string `json:"version"`
	Policy        string `json:"policy"`
	PinnedVersion string `json:"pinned_version,omitempty"`

	CurrentVersion string `json:"current_version,omitempty"`

	ReleaseFound  bool `json:"release_found"`
	PlatformMatch bool `json:"platform_match"`
	Approved      bool `json:"approved"`
	Revoked       bool `json:"revoked"`

	ReleaseChannel string `json:"release_channel,omitempty"`
	ReleaseOS      string `json:"release_os,omitempty"`
	Architecture   string `json:"architecture,omitempty"`

	NewerThanCurrent bool `json:"newer_than_current"`
	Eligible         bool `json:"eligible"`

	Blockers []string `json:"blockers"`
}

type RolloutPlan struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	NodeID   string `json:"node_id"`

	CoreType string `json:"core_type"`

	Policy        string `json:"policy"`
	PinnedVersion string `json:"pinned_version,omitempty"`

	BaseGeneration     int64 `json:"base_generation"`
	ProposedGeneration int64 `json:"proposed_generation"`

	FromVersion string `json:"from_version,omitempty"`

	TargetCoreReleaseID string `json:"target_core_release_id,omitempty"`
	TargetVersion       string `json:"target_version,omitempty"`
	TargetChannel       string `json:"target_channel,omitempty"`

	DeploymentID string `json:"deployment_id,omitempty"`

	OutcomeStatus string     `json:"outcome_status,omitempty"`
	OutcomeAt     *time.Time `json:"outcome_at,omitempty"`
	OutcomeReason string     `json:"outcome_reason,omitempty"`

	Status string `json:"status"`

	Blockers []string `json:"blockers"`

	DesiredStatePreview *DesiredState `json:"desired_state_preview,omitempty"`

	CreatedBy string `json:"created_by"`

	ApprovedBy string     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`

	ExecutedAt  *time.Time `json:"executed_at,omitempty"`
	CancelledAt *time.Time `json:"cancelled_at,omitempty"`

	FailureReason string `json:"failure_reason,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
