package model

import (
	"encoding/json"
	"time"
)

type VPNClientConnection struct {
	// Reviewed imported or canonical cascade transport metadata. Never accepted from HTTP input.
	ImportedProfile json.RawMessage `json:"-"`

	Config          string     `json:"config,omitempty"`
	ConfigFilename  string     `json:"config_filename,omitempty"`
	ConfigExpiresAt *time.Time `json:"config_expires_at,omitempty"`
	ClientID        string     `json:"client_id"`
	ClientName      string     `json:"client_name"`
	BrandName       string     `json:"brand_name"`

	ServiceID        string `json:"service_id"`
	ServiceName      string `json:"service_name"`
	SubscriptionName string `json:"-"`

	Address string `json:"address"`
	Port    int    `json:"port"`

	RuntimeCore      string `json:"runtime_core,omitempty"`
	Protocol         string `json:"protocol"`
	Transport        string `json:"transport"`
	Security         string `json:"security"`
	AmneziaWGVersion string `json:"amneziawg_version,omitempty"`

	UUID     string `json:"uuid"`
	Username string `json:"username,omitempty"`

	ServerName  string `json:"server_name"`
	Fingerprint string `json:"fingerprint"`
	ShortID     string `json:"short_id"`

	// Client-side REALITY credential.
	// This is the X25519 public value corresponding
	// to the node-local private key.
	Password string `json:"password"`

	URI string `json:"uri,omitempty"`
}
