package xrayprofile

import (
	"crypto/ecdh"
	"encoding/base64"
)

// SourceMaterial is node-local inspection data. Secret values and file paths
// cannot accidentally enter an encoded receipt or control-plane response.
type SourceMaterial struct {
	InboundTag       string       `json:"inbound_tag"`
	Security         string       `json:"security"`
	Local            LocalSecrets `json:"-"`
	RealityPublicKey string       `json:"-"`
}

// InspectSourceMaterials accepts the same reviewed, client-free source template
// as Project. A live daemon's dynamically expanded configuration is not silently
// reduced to this template: the handoff must separately verify its identity.
func InspectSourceMaterials(raw []byte) ([]SourceMaterial, Dependencies, error) {
	cfg, err := decode(raw)
	if err != nil || validateConfig(cfg, true) != nil {
		return nil, Dependencies{}, ErrProfile
	}
	out := []SourceMaterial{}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		stream := in["streamSettings"].(map[string]any)
		m := SourceMaterial{InboundTag: str(in["tag"]), Security: str(stream["security"])}
		if m.Security == "reality" {
			r := stream["realitySettings"].(map[string]any)
			m.Local.RealityPrivateKey = str(r["privateKey"])
			b, _ := base64.RawURLEncoding.DecodeString(m.Local.RealityPrivateKey)
			key, _ := ecdh.X25519().NewPrivateKey(b)
			m.RealityPublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		} else {
			cert := stream["tlsSettings"].(map[string]any)["certificates"].([]any)[0].(map[string]any)
			m.Local.CertificateFile, m.Local.KeyFile = str(cert["certificateFile"]), str(cert["keyFile"])
		}
		out = append(out, m)
	}
	return out, dependenciesFromConfig(cfg), nil
}
