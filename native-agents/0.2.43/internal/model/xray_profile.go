package model

import "encoding/json"

// XrayProfileSpec preserves a reviewed imported graph. Config contains no
// clients, private keys or certificate paths. Runtime secrets are resolved by
// the agent through the ordinary service-bound Reality/TLS identities.
type XrayProfileSpec struct {
	Version  int                  `json:"version"`
	SHA256   string               `json:"sha256"`
	Config   json.RawMessage      `json:"config"`
	Bindings []XrayProfileBinding `json:"bindings"`
}

type XrayProfileBinding struct {
	ServiceID        string `json:"service_id"`
	InboundTag       string `json:"inbound_tag"`
	RealityPublicKey string `json:"reality_public_key,omitempty"`
}
