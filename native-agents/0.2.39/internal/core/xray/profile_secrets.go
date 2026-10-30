package xray

import (
	"fmt"
	"os"
	"path/filepath"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

// Imported listeners keep the original public identity. Missing material is an
// adoption/repair error, never permission to generate an unrelated replacement.
func (d *Driver) profileRealitySecret(service model.ServiceSpec, profile *model.XrayProfileSpec) (string, string, error) {
	if profile == nil {
		return d.ensureRealitySecret(service)
	}
	if err := validateRealitySecretRef(service); err != nil {
		return "", "", err
	}
	var expected string
	for _, binding := range profile.Bindings {
		if binding.ServiceID == service.ID {
			expected = binding.RealityPublicKey
		}
	}
	if expected == "" {
		return "", "", xrayprofile.ErrProfile
	}
	name := filepath.Join(d.realitySecretsDir(), service.ID+".key")
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 128 {
		return "", "", fmt.Errorf("imported Reality key is missing or has unsafe permissions")
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return "", "", fmt.Errorf("imported Reality key is unavailable")
	}
	key, err := decodeRealityPrivateKey(string(raw))
	if err != nil {
		return "", "", fmt.Errorf("imported Reality key is invalid")
	}
	public := encodeRealityPublicKey(key.PublicKey())
	if public != expected {
		return "", "", fmt.Errorf("imported Reality public identity does not match")
	}
	return encodeRealityPrivateKey(key), public, nil
}
