package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"vpn-platform/internal/model"
)

var ErrAccessFence = errors.New("Xray access generation is fenced")

type accessFence struct {
	Generation   int64  `json:"generation"`
	Digest       string `json:"digest"`
	ConfigSHA256 string `json:"config_sha256"`
	Blocked      bool   `json:"blocked"`
	Cascades     bool   `json:"cascades,omitempty"`
}

func configDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func (d *Driver) readAccessFence() (accessFence, error) {
	var f accessFence
	path := filepath.Join(d.xrayDir(), "access-fence.json")
	info, err := os.Lstat(path)
	if err != nil {
		return f, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
		return f, ErrAccessFence
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if json.Unmarshal(raw, &f) != nil || f.Generation <= 0 || len(f.Digest) != 64 || len(f.ConfigSHA256) != 64 {
		return f, ErrAccessFence
	}
	return f, nil
}
func (d *Driver) writeAccessFence(f accessFence) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(d.xrayDir(), ".access-fence-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(raw); err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temp.Name(), filepath.Join(d.xrayDir(), "access-fence.json")); err != nil {
		return err
	}
	dir, err := os.Open(d.xrayDir())
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (d *Driver) accessIntent(state model.DesiredState) (accessFence, error) {
	if state.Generation <= 0 {
		return accessFence{}, ErrAccessFence
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return accessFence{}, err
	}
	next := accessFence{Generation: state.Generation, Digest: configDigest(raw), Cascades: state.XrayCascades != nil}
	prior, err := d.readAccessFence()
	if err != nil && !os.IsNotExist(err) {
		return next, err
	}
	if prior.Generation > next.Generation || (prior.Generation == next.Generation && prior.Digest != next.Digest) {
		return next, ErrAccessFence
	}
	return next, nil
}

// This also runs as ExecStartPre, so a host reboot or manual service start cannot
// bypass the durable block left by a failed revocation.
func (d *Driver) CheckAccessFence() error {
	f, err := d.readAccessFence()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || f.Blocked {
		return ErrAccessFence
	}
	raw, err := os.ReadFile(d.configPath())
	if err != nil || configDigest(raw) != f.ConfigSHA256 {
		return ErrAccessFence
	}
	return nil
}

// Authorization fingerprints include listener identity and the complete native
// credential object. Removed listeners, client keys, or WireGuard peers count as
// revocations; changing only the core build or TLS file paths does not.
func authorizationSet(raw []byte) (map[string]bool, error) {
	var config struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				Clients []json.RawMessage `json:"clients"`
				Peers   []json.RawMessage `json:"peers"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &config) != nil {
		return nil, ErrAccessFence
	}
	set := map[string]bool{}
	for _, in := range config.Inbounds {
		for _, credential := range append(in.Settings.Clients, in.Settings.Peers...) {
			var value any
			if json.Unmarshal(credential, &value) != nil {
				return nil, ErrAccessFence
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			set[in.Tag+"/"+in.Protocol+"/"+configDigest(canonical)] = true
		}
	}
	return set, nil
}
func authorizationRemoved(before, after []byte) (bool, error) {
	old, err := authorizationSet(before)
	if err != nil {
		return false, err
	}
	next, err := authorizationSet(after)
	if err != nil {
		return false, err
	}
	for key := range old {
		if !next[key] {
			return true, nil
		}
	}
	return false, nil
}
