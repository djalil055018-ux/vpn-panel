package xray

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpn-platform/internal/model"
)

func (d *Driver) resolveTLSCertificates(state model.DesiredState) (model.DesiredState, error) {
	state.Services = append([]model.ServiceSpec(nil), state.Services...)
	for i := range state.Services {
		s := &state.Services[i]
		if s.Security != "tls" {
			continue
		}
		if s.TLS == nil {
			return state, fmt.Errorf("TLS certificate is missing for service %s", s.ID)
		}
		if !realityServiceIDPattern.MatchString(s.TLS.CertificateID) {
			return state, fmt.Errorf("invalid TLS certificate identity")
		}
		root, err := filepath.Abs(filepath.Join(d.BaseDir, "certificates", s.TLS.CertificateID))
		if err != nil {
			return state, err
		}
		current := filepath.Join(root, "current")
		// A renewal changes current atomically. Every resolved path must remain
		// under this certificate's directory, including symlink resolution.
		for _, name := range []string{"fullchain.pem", "private.key"} {
			resolved, err := filepath.EvalSymlinks(filepath.Join(current, name))
			if err != nil {
				return state, fmt.Errorf("TLS certificate files are unavailable for service %s", s.ID)
			}
			rel, err := filepath.Rel(root, resolved)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return state, fmt.Errorf("TLS certificate path escapes its directory")
			}
			info, err := os.Stat(resolved)
			if err != nil || !info.Mode().IsRegular() {
				return state, fmt.Errorf("TLS certificate file is not regular")
			}
			if name == "private.key" && info.Mode().Perm()&0077 != 0 {
				return state, fmt.Errorf("TLS private key permissions must be owner-only")
			}
		}
		pair, err := tls.LoadX509KeyPair(filepath.Join(current, "fullchain.pem"), filepath.Join(current, "private.key"))
		if err != nil || len(pair.Certificate) == 0 {
			return state, fmt.Errorf("TLS certificate and key validation failed")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return state, fmt.Errorf("invalid TLS certificate")
		}
		now := time.Now()
		if leaf.VerifyHostname(s.TLS.ServerName) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return state, fmt.Errorf("TLS certificate hostname or validity check failed")
		}
		copy := *s.TLS
		copy.CertificateFile = filepath.Join(current, "fullchain.pem")
		copy.KeyFile = filepath.Join(current, "private.key")
		s.TLS = &copy
	}
	return state, nil
}
