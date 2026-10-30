package xrayprofile

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"vpn-platform/internal/model"
)

const MinimumAgent = "0.2.31"
const MinimumCore = "26.9.9"

// Returned only to an offline owner adoption workflow. Never include these
// node-local values in a desired state, API response, audit record or log.
type LocalSecrets struct {
	RealityPrivateKey string `json:"-"`
	CertificateFile   string `json:"-"`
	KeyFile           string `json:"-"`
}

func bindingsFor(cfg map[string]any, bindings []model.XrayProfileBinding) (map[string]string, error) {
	inbounds := cfg["inbounds"].([]any)
	if len(bindings) != len(inbounds) {
		return nil, ErrProfile
	}
	tags := map[string]bool{}
	for _, value := range inbounds {
		tags[str(value.(map[string]any)["tag"])] = true
	}
	result := map[string]string{}
	services := map[string]bool{}
	for _, b := range bindings {
		if !uuid.MatchString(b.ServiceID) || !tags[b.InboundTag] || result[b.InboundTag] != "" || services[b.ServiceID] {
			return nil, ErrProfile
		}
		result[b.InboundTag] = b.ServiceID
		services[b.ServiceID] = true
	}
	return result, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func profileDigest(cfg map[string]any, bindings []model.XrayProfileBinding) string {
	raw, _ := json.Marshal(struct {
		Config   map[string]any
		Bindings []model.XrayProfileBinding
	}{cfg, bindings})
	return digest(raw)
}

// Project accepts only the narrowly reviewed source graph. Unsupported fields
// fail closed instead of silently disappearing during a migration.
func Project(raw []byte, bindings []model.XrayProfileBinding) (*model.XrayProfileSpec, map[string]LocalSecrets, error) {
	cfg, err := decode(raw)
	if err != nil || validateConfig(cfg, true) != nil {
		return nil, nil, ErrProfile
	}
	byTag, err := bindingsFor(cfg, bindings)
	if err != nil {
		return nil, nil, err
	}
	bindings = append([]model.XrayProfileBinding(nil), bindings...)
	for _, b := range bindings {
		if b.RealityPublicKey != "" {
			return nil, nil, ErrProfile
		}
	}
	secrets := map[string]LocalSecrets{}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		stream := in["streamSettings"].(map[string]any)
		var local LocalSecrets
		if str(stream["security"]) == "reality" {
			r := stream["realitySettings"].(map[string]any)
			local.RealityPrivateKey = str(r["privateKey"])
			keyBytes, _ := base64.RawURLEncoding.DecodeString(local.RealityPrivateKey)
			key, _ := ecdh.X25519().NewPrivateKey(keyBytes)
			for i := range bindings {
				if bindings[i].InboundTag == str(in["tag"]) {
					bindings[i].RealityPublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
				}
			}
			delete(r, "privateKey")
		} else {
			t := stream["tlsSettings"].(map[string]any)
			cert := t["certificates"].([]any)[0].(map[string]any)
			local.CertificateFile, local.KeyFile = str(cert["certificateFile"]), str(cert["keyFile"])
			t["certificates"] = []any{}
		}
		secrets[byTag[str(in["tag"])]] = local
	}
	if validateConfig(cfg, false) != nil {
		return nil, nil, ErrProfile
	}
	canonical, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, ErrProfile
	}
	result := &model.XrayProfileSpec{Version: 1, SHA256: profileDigest(cfg, bindings), Config: canonical, Bindings: bindings}
	return result, secrets, nil
}

func parse(spec *model.XrayProfileSpec) (map[string]any, map[string]string, error) {
	if spec == nil || spec.Version != 1 {
		return nil, nil, ErrProfile
	}
	cfg, err := decode(spec.Config)
	if err != nil || validateConfig(cfg, false) != nil {
		return nil, nil, ErrProfile
	}
	if profileDigest(cfg, spec.Bindings) != spec.SHA256 {
		return nil, nil, ErrProfile
	}
	bindings, err := bindingsFor(cfg, spec.Bindings)
	if err != nil {
		return nil, nil, err
	}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		reality := str(in["streamSettings"].(map[string]any)["security"]) == "reality"
		for _, b := range spec.Bindings {
			if b.InboundTag != str(in["tag"]) {
				continue
			}
			if reality {
				key, err := base64.RawURLEncoding.DecodeString(b.RealityPublicKey)
				if err != nil || len(key) != 32 {
					return nil, nil, ErrProfile
				}
			} else if b.RealityPublicKey != "" {
				return nil, nil, ErrProfile
			}
		}
	}
	return cfg, bindings, nil
}

func Validate(spec *model.XrayProfileSpec) error {
	_, _, err := parse(spec)
	return err
}
