package model

type AgentRelease struct {
	Version         string `json:"version"`
	BinarySHA256    string `json:"binary_sha256"`
	InstallerSHA256 string `json:"installer_sha256"`
}

type AgentUpdateAssignment struct {
	JobID       string       `json:"job_id"`
	RunID       string       `json:"run_id"`
	NodeID      string       `json:"node_id"`
	ClaimID     string       `json:"claim_id"`
	FromVersion string       `json:"from_version"`
	CanExecute  bool         `json:"can_execute"`
	Release     AgentRelease `json:"release"`
}

type AgentUpdateReport struct {
	ClaimID      string `json:"claim_id"`
	Status       string `json:"status"`
	BinarySHA256 string `json:"binary_sha256"`
	Code         string `json:"code"`
}
