package model

import (
	"encoding/json"
	"time"
)

// A missing field means the observation is unavailable. A present null means
// the source explicitly recorded that no connection/reset has ever happened.
type DirectoryTime struct{ Value *time.Time }

func (d DirectoryTime) MarshalJSON() ([]byte, error) { return json.Marshal(d.Value) }

// Only display metadata belongs here. Credentials, subscription aliases, source
// records and arbitrary JSON must never be added to this public projection.
type ClientDirectory struct {
	NumericID          *int64         `json:"numeric_id,omitempty"`
	TelegramID         *string        `json:"telegram_id,omitempty"`
	Tag                *string        `json:"tag,omitempty"`
	Groups             []string       `json:"groups"`
	LastNodeName       *string        `json:"last_node_name,omitempty"`
	FirstConnectedAt   *DirectoryTime `json:"first_connected_at,omitempty"`
	LastOnlineAt       *DirectoryTime `json:"last_online_at,omitempty"`
	LastTrafficResetAt *DirectoryTime `json:"last_traffic_reset_at,omitempty"`
	LifetimeUsedBytes  *int64         `json:"lifetime_used_bytes,omitempty"`
	ConnectionState    string         `json:"connection_state"`
	SourceStatus       string         `json:"source_status,omitempty"`
	SourceObservedAt   *time.Time     `json:"source_observed_at,omitempty"`
}
