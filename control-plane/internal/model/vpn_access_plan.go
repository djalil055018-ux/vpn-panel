package model

import "time"

type VPNAccessPlan struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Code      string    `json:"code"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type VPNAccessPlanDetail struct {
	VPNAccessPlan
	ServiceIDs   []string `json:"service_ids"`
	ClientIDs    []string `json:"client_ids"`
	BotClientIDs []string `json:"bot_client_ids"`
}

type NodeRebuildResult struct {
	NodeID     string `json:"node_id"`
	Generation int64  `json:"generation"`
}

type VPNAccessPlanMutation struct {
	Plan     *VPNAccessPlan      `json:"plan,omitempty"`
	Changed  bool                `json:"changed"`
	Rebuilds []NodeRebuildResult `json:"rebuilds"`
}
