package model

type RealitySpec struct {
	Destination string `json:"destination"`
	ServerName  string `json:"server_name"`
	Fingerprint string `json:"fingerprint"`
	ShortID     string `json:"short_id"`
	SecretRef   string `json:"secret_ref"`

	// Populated only inside Node Agent runtime.
	// Never serialized into Desired State.
	PrivateKey string `json:"-"`
}

type RealityPublicMaterial struct {
	ServiceID string `json:"service_id"`
	PublicKey string `json:"public_key"`
}
