package model

import "time"

const XrayCascadeMinimumAgent = "0.2.34"

func XrayCascadeAgentCompatible(version string) bool { return agentMinimumPatch(version, 34) }

// Public definition. Transit credentials exist only in the private database
// and signed node assignments; they cannot be supplied or read through this API.
type VPNCascade struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	Name                string    `json:"name"`
	PlanID              string    `json:"plan_id"`
	EntryServiceID      string    `json:"entry_service_id"`
	ExitServiceID       string    `json:"exit_service_id"`
	EntryNodeID         string    `json:"entry_node_id"`
	ExitNodeID          string    `json:"exit_node_id"`
	EntryPort           int       `json:"entry_port"`
	Enabled             bool      `json:"enabled"`
	ConnectRaceIP       string    `json:"connect_race_ip,omitempty"`
	ConnectRaceClients  bool      `json:"connect_race_clients,omitempty"`
	ConnectRaceAttempts int       `json:"connect_race_attempts,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type VPNCascadeInput struct {
	Name                string     `json:"name"`
	PlanID              string     `json:"plan_id"`
	EntryServiceID      string     `json:"entry_service_id"`
	ExitServiceID       string     `json:"exit_service_id"`
	EntryPort           int        `json:"entry_port"`
	Enabled             bool       `json:"enabled"`
	ConnectRaceIP       *string    `json:"connect_race_ip,omitempty"`
	ConnectRaceClients  *bool      `json:"connect_race_clients,omitempty"`
	ConnectRaceAttempts *int       `json:"connect_race_attempts,omitempty"`
	ExpectedUpdatedAt   *time.Time `json:"expected_updated_at,omitempty"`
}

type VPNCascadeMutation struct {
	Cascade  *VPNCascade         `json:"cascade,omitempty"`
	Changed  bool                `json:"changed"`
	Rebuilds []NodeRebuildResult `json:"rebuilds"`
}

type VPNCascadeView struct {
	VPNCascade
	State                  string `json:"state"`
	EntryNodeName          string `json:"entry_node_name"`
	ExitNodeName           string `json:"exit_node_name"`
	PlanName               string `json:"plan_name"`
	EntryAgentVersion      string `json:"entry_agent_version"`
	ExitAgentVersion       string `json:"exit_agent_version"`
	EntryDesiredGeneration int64  `json:"entry_desired_generation"`
	EntryAppliedGeneration int64  `json:"entry_applied_generation"`
	ExitDesiredGeneration  int64  `json:"exit_desired_generation"`
	ExitAppliedGeneration  int64  `json:"exit_applied_generation"`
}
