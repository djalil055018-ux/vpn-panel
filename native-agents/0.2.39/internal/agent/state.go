package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type LocalState struct {
	NodeID            string `json:"node_id"`
	TenantID          string `json:"tenant_id"`
	AgentToken        string `json:"agent_token"`
	AppliedGeneration int64  `json:"applied_generation"`

	FailedGeneration int64 `json:"failed_generation,omitempty"`
	FailureCount     int   `json:"failure_count,omitempty"`
	NextRetryUnix    int64 `json:"next_retry_unix,omitempty"`
}

func LoadState(path string) (LocalState, error) {
	raw, err := os.ReadFile(path)

	if os.IsNotExist(err) {
		return LocalState{}, nil
	}

	if err != nil {
		return LocalState{}, err
	}

	var state LocalState

	if err := json.Unmarshal(raw, &state); err != nil {
		return LocalState{}, err
	}

	return state, nil
}

func SaveState(path string, state LocalState) error {
	if err := os.MkdirAll(
		filepath.Dir(path),
		0700,
	); err != nil {
		return err
	}

	raw, err := json.MarshalIndent(
		state,
		"",
		"  ",
	)
	if err != nil {
		return err
	}

	tmp := path + ".new"

	if err := os.WriteFile(
		tmp,
		raw,
		0600,
	); err != nil {
		return err
	}

	if err := os.Chmod(tmp, 0600); err != nil {
		return err
	}

	return os.Rename(
		tmp,
		path,
	)
}
