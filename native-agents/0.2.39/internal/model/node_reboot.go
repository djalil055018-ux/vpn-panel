package model

import "time"

type NodeRebootJob struct {
	ID          string     `json:"id"`
	NodeID      string     `json:"node_id"`
	NodeName    string     `json:"node_name"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ScheduledAt *time.Time `json:"scheduled_at,omitempty"`
}

type NodeRebootJobClaimRequest struct {
	OwnerInstanceID string `json:"owner_instance_id"`
}

type NodeRebootJobGrant struct {
	JobID string `json:"job_id"`
}

type NodeRebootJobResult struct {
	JobID           string `json:"job_id"`
	OwnerInstanceID string `json:"owner_instance_id"`
	Status          string `json:"status"`
	FailureCode     string `json:"failure_code,omitempty"`
}
