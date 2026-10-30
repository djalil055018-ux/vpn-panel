package hysteria

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"vpn-platform/internal/model"
)

var ErrTLSMaterial = errors.New("Hysteria TLS material unavailable or invalid")
var certificateIdentity = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var materialDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CertificateRuntime leaves root-only ACME originals in place. Each published
// pair is immutable and readable only by root and the managed core's group.
// Configs reference one concrete version: two file reads cannot cross a renewal
// of a mutable current link. Changing a certificate therefore requires a staged
// config replacement, coordinated by the driver with capture/stop/start/rollback.
type CertificateRuntime struct {
	base string
	gid  int
}

func NewCertificateRuntime(base string, gid int) (*CertificateRuntime, error) {
	if os.Geteuid() != 0 || gid < 0 || !filepath.IsAbs(base) || filepath.Clean(base) != base || protectedDirectory(base, false) != nil {
		return nil, ErrTLSMaterial
	}
	return &CertificateRuntime{base: base, gid: gid}, nil
}

func readTLSFile(path string, limit int64, mode os.FileMode, gid int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || !ownedBy(info, 0, gid) || info.Size() <= 0 || info.Size() > limit {
		return nil, ErrTLSMaterial
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrTLSMaterial
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, ErrTLSMaterial
	}
	return raw, nil
}

func validTLSPair(certificate, key []byte, domain string) bool {
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	now := time.Now()
	return leaf.VerifyHostname(domain) == nil && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}

func (r *CertificateRuntime) source(spec model.TLSSpec) ([]byte, []byte, error) {
	if !certificateIdentity.MatchString(spec.CertificateID) || spec.ServerName == "" {
		return nil, nil, ErrTLSMaterial
	}
	root := filepath.Join(r.base, "certificates", spec.CertificateID)
	versions := filepath.Join(root, "versions")
	for _, dir := range []string{r.base, filepath.Join(r.base, "certificates"), root, versions} {
		if protectedDirectory(dir, false) != nil {
			return nil, nil, ErrTLSMaterial
		}
	}
	// Resolve the directory exactly once. A concurrent atomic renewal can select
	// either complete version, but cannot combine its certificate with another key.
	version, err := filepath.EvalSymlinks(filepath.Join(root, "current"))
	if err != nil || filepath.Dir(version) != versions || protectedDirectory(version, false) != nil {
		return nil, nil, ErrTLSMaterial
	}
	certificate, err := readTLSFile(filepath.Join(version, "fullchain.pem"), 1<<20, 0644, -1)
	if err != nil {
		certificate, err = readTLSFile(filepath.Join(version, "fullchain.pem"), 1<<20, 0600, -1)
	}
	if err != nil {
		return nil, nil, err
	}
	key, err := readTLSFile(filepath.Join(version, "private.key"), 64<<10, 0600, -1)
	if err != nil {
		return nil, nil, err
	}
	if !validTLSPair(certificate, key, spec.ServerName) {
		return nil, nil, ErrTLSMaterial
	}
	return certificate, key, nil
}

func runtimeTLSDirectory(path string, gid int) error {
	if protectedDirectory(path, true) != nil || os.Chown(path, 0, gid) != nil || os.Chmod(path, 0750) != nil || syncDirectory(path) != nil {
		return ErrTLSMaterial
	}
	return nil
}
func writeRuntimeTLS(path string, raw []byte, gid int) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrTLSMaterial
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Chown(0, gid)
	}
	if err == nil {
		err = f.Chmod(0640)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrTLSMaterial
	}
	return nil
}
func (r *CertificateRuntime) verifyPublished(target string, certificate, key []byte) error {
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0750 || !ownedBy(info, 0, r.gid) {
		return ErrTLSMaterial
	}
	cert, err := readTLSFile(filepath.Join(target, "fullchain.pem"), 1<<20, 0640, r.gid)
	if err != nil || !bytes.Equal(cert, certificate) {
		return ErrTLSMaterial
	}
	private, err := readTLSFile(filepath.Join(target, "private.key"), 64<<10, 0640, r.gid)
	if err != nil || !bytes.Equal(private, key) {
		return ErrTLSMaterial
	}
	return nil
}

func (r *CertificateRuntime) Stage(spec model.TLSSpec) (model.TLSSpec, error) {
	certificate, key, err := r.source(spec)
	if err != nil {
		return model.TLSSpec{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write(certificate)
	_, _ = hash.Write(key)
	digest := hex.EncodeToString(hash.Sum(nil))
	root := filepath.Join(r.base, "hysteria2")
	certificates := filepath.Join(root, "certificates")
	identity := filepath.Join(certificates, spec.CertificateID)
	versions := filepath.Join(identity, "versions")
	for _, dir := range []string{root, certificates, identity, versions} {
		if runtimeTLSDirectory(dir, r.gid) != nil {
			return model.TLSSpec{}, ErrTLSMaterial
		}
	}
	target := filepath.Join(versions, digest)
	if _, err = os.Lstat(target); os.IsNotExist(err) {
		temp, err := os.MkdirTemp(versions, ".tls-")
		if err != nil {
			return model.TLSSpec{}, ErrTLSMaterial
		}
		defer os.RemoveAll(temp)
		if writeRuntimeTLS(filepath.Join(temp, "fullchain.pem"), certificate, r.gid) != nil || writeRuntimeTLS(filepath.Join(temp, "private.key"), key, r.gid) != nil || os.Chown(temp, 0, r.gid) != nil || os.Chmod(temp, 0750) != nil || syncDirectory(temp) != nil {
			return model.TLSSpec{}, ErrTLSMaterial
		}
		if err = os.Rename(temp, target); err != nil && r.verifyPublished(target, certificate, key) != nil {
			return model.TLSSpec{}, ErrTLSMaterial
		}
	} else if err != nil {
		return model.TLSSpec{}, ErrTLSMaterial
	}
	if r.verifyPublished(target, certificate, key) != nil || syncDirectory(versions) != nil {
		return model.TLSSpec{}, ErrTLSMaterial
	}
	spec.CertificateFile = filepath.Join(target, "fullchain.pem")
	spec.KeyFile = filepath.Join(target, "private.key")
	return spec, nil
}

// A snapshot may reference an expired certificate so that a new valid revision
// can replace it. Activation/rollback must request current validity explicitly.
func (r *CertificateRuntime) published(spec model.TLSSpec, digest string, requireCurrent bool) (model.TLSSpec, error) {
	if !certificateIdentity.MatchString(spec.CertificateID) || !materialDigest.MatchString(digest) {
		return model.TLSSpec{}, ErrTLSMaterial
	}
	root := filepath.Join(r.base, "hysteria2")
	certificates := filepath.Join(root, "certificates")
	identity := filepath.Join(certificates, spec.CertificateID)
	versions := filepath.Join(identity, "versions")
	target := filepath.Join(versions, digest)
	for _, dir := range []string{r.base, root, certificates, identity, versions, target} {
		if protectedDirectory(dir, false) != nil {
			return model.TLSSpec{}, ErrTLSMaterial
		}
	}
	cert, err := readTLSFile(filepath.Join(target, "fullchain.pem"), 1<<20, 0640, r.gid)
	if err != nil {
		return model.TLSSpec{}, err
	}
	key, err := readTLSFile(filepath.Join(target, "private.key"), 64<<10, 0640, r.gid)
	if err != nil {
		return model.TLSSpec{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write(cert)
	_, _ = hash.Write(key)
	if hex.EncodeToString(hash.Sum(nil)) != digest || r.verifyPublished(target, cert, key) != nil {
		return model.TLSSpec{}, ErrTLSMaterial
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil || len(pair.Certificate) == 0 {
		return model.TLSSpec{}, ErrTLSMaterial
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(spec.ServerName) != nil {
		return model.TLSSpec{}, ErrTLSMaterial
	}
	if requireCurrent && !validTLSPair(cert, key, spec.ServerName) {
		return model.TLSSpec{}, ErrTLSMaterial
	}
	spec.CertificateFile = filepath.Join(target, "fullchain.pem")
	spec.KeyFile = filepath.Join(target, "private.key")
	return spec, nil
}
