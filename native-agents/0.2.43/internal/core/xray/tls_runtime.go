package xray

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
	"vpn-platform/internal/model"
)

// Root retains the ACME originals. Xray receives read-only group access to a
// separate immutable runtime version only when a TLS service uses it.
func (d *Driver) publishTLSRuntime(spec model.TLSSpec, gid int) (model.TLSSpec, error) {
	certificate, err := os.ReadFile(spec.CertificateFile)
	if err != nil {
		return spec, err
	}
	key, err := os.ReadFile(spec.KeyFile)
	if err != nil {
		return spec, err
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil || len(pair.Certificate) == 0 {
		return spec, fmt.Errorf("TLS material changed during publication")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(spec.ServerName) != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return spec, fmt.Errorf("TLS certificate validation failed before publication")
	}
	sum := sha256.Sum256(append(append([]byte{}, certificate...), key...))
	version := hex.EncodeToString(sum[:])
	parent := filepath.Join(d.xrayDir(), "certificates")
	root := filepath.Join(parent, spec.CertificateID)
	versions := filepath.Join(root, "versions")
	target := filepath.Join(versions, version)
	for _, dir := range []string{parent, root, versions} {
		if err = os.MkdirAll(dir, 0750); err != nil {
			return spec, err
		}
		if err = os.Chown(dir, 0, gid); err != nil {
			return spec, err
		}
		if err = os.Chmod(dir, 0750); err != nil {
			return spec, err
		}
	}
	if _, err = os.Stat(target); os.IsNotExist(err) {
		temp, err := os.MkdirTemp(versions, ".candidate-")
		if err != nil {
			return spec, err
		}
		defer os.RemoveAll(temp)
		for name, data := range map[string][]byte{"fullchain.pem": certificate, "private.key": key} {
			p := filepath.Join(temp, name)
			if err = os.WriteFile(p, data, 0600); err != nil {
				return spec, err
			}
			if err = os.Chown(p, 0, gid); err != nil {
				return spec, err
			}
			if err = os.Chmod(p, 0640); err != nil {
				return spec, err
			}
		}
		if err = os.Chown(temp, 0, gid); err != nil {
			return spec, err
		}
		if err = os.Chmod(temp, 0750); err != nil {
			return spec, err
		}
		if err = os.Rename(temp, target); err != nil {
			if _, e := os.Stat(target); e != nil {
				return spec, err
			}
		}
	} else if err != nil {
		return spec, err
	}
	link := filepath.Join(root, fmt.Sprintf(".current-%d", time.Now().UnixNano()))
	defer os.Remove(link)
	if err = os.Symlink(filepath.Join("versions", version), link); err != nil {
		return spec, err
	}
	if err = os.Rename(link, filepath.Join(root, "current")); err != nil {
		return spec, err
	}
	spec.CertificateFile = filepath.Join(root, "current", "fullchain.pem")
	spec.KeyFile = filepath.Join(root, "current", "private.key")
	return spec, nil
}

func (d *Driver) prepareTLSRuntime(state model.DesiredState) (model.DesiredState, error) {
	state.Services = append([]model.ServiceSpec(nil), state.Services...)
	for i := range state.Services {
		s := &state.Services[i]
		if s.Security != "tls" {
			continue
		}
		group, err := user.LookupGroup("vpnplatform-xray")
		if err != nil {
			return state, fmt.Errorf("Xray runtime group unavailable")
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			return state, err
		}
		if s.TLS == nil {
			return state, fmt.Errorf("missing resolved TLS certificate")
		}
		copy, err := d.publishTLSRuntime(*s.TLS, gid)
		if err != nil {
			return state, fmt.Errorf("TLS runtime publication failed")
		}
		s.TLS = &copy
	}
	return state, nil
}

// Renewals refresh the existing runtime link without restarting Xray. Xray's
// certificate watcher reloads the files; unused certificates are not published.
func (d *Driver) RefreshTLSCertificate(id, domain string) error {
	if !realityServiceIDPattern.MatchString(id) {
		return fmt.Errorf("invalid certificate id")
	}
	if _, err := os.Stat(filepath.Join(d.xrayDir(), "certificates", id, "current")); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	state := model.DesiredState{Services: []model.ServiceSpec{{Security: "tls", TLS: &model.TLSSpec{CertificateID: id, ServerName: domain}}}}
	resolved, err := d.resolveTLSCertificates(state)
	if err != nil {
		return err
	}
	_, err = d.prepareTLSRuntime(resolved)
	return err
}
