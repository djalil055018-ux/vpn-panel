package hysteria

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
	"vpn-platform/internal/model"
)

const tlsFixtureID = "44444444-4444-4444-8444-444444444444"

func fixturePair(t *testing.T, expires time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "tls-probe.invalid"}, DNSNames: []string{"tls-probe.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}
func tlsFixture(t *testing.T) (*CertificateRuntime, model.TLSSpec, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("runtime publication ownership requires root")
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "certificates", tlsFixtureID)
	if err := os.MkdirAll(filepath.Join(root, "versions"), 0700); err != nil {
		t.Fatal(err)
	}
	r, err := NewCertificateRuntime(base, 65534)
	if err != nil {
		t.Fatal(err)
	}
	addTLSVersion(t, root, "one", time.Now().Add(time.Hour))
	if err := os.Symlink(filepath.Join("versions", "one"), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	return r, model.TLSSpec{CertificateID: tlsFixtureID, ServerName: "tls-probe.invalid"}, root
}
func addTLSVersion(t *testing.T, root, name string, expires time.Time) {
	t.Helper()
	dir := filepath.Join(root, "versions", name)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cert, key := fixturePair(t, expires)
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), cert, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
}
func rotateTLSVersion(root, name string) error {
	temp := filepath.Join(root, ".current-next")
	if err := os.Symlink(filepath.Join("versions", name), temp); err != nil {
		return err
	}
	return os.Rename(temp, filepath.Join(root, "current"))
}
func TestTLSStagePermissionsOriginalsAndRenewalIsolation(t *testing.T) {
	r, spec, root := tlsFixture(t)
	before, _ := os.ReadFile(filepath.Join(root, "current", "private.key"))
	spec.KeyFile = "/must-not-read/private"
	spec.CertificateFile = "/must-not-read/certificate"
	first, err := r.Stage(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{first.CertificateFile, first.KeyFile} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0640 || !ownedBy(info, 0, 65534) {
			t.Fatal("runtime TLS ownership or permissions invalid")
		}
	}
	original, _ := os.ReadFile(filepath.Join(root, "current", "private.key"))
	if !bytes.Equal(original, before) {
		t.Fatal("source private key changed")
	}
	again, err := r.Stage(spec)
	if err != nil || again != first {
		t.Fatal("idempotent publication changed version")
	}
	addTLSVersion(t, root, "two", time.Now().Add(2*time.Hour))
	if err := rotateTLSVersion(root, "two"); err != nil {
		t.Fatal(err)
	}
	second, err := r.Stage(spec)
	if err != nil || second.KeyFile == first.KeyFile {
		t.Fatal("renewal did not stage a new immutable pair")
	}
	retained, _ := os.ReadFile(first.KeyFile)
	if !bytes.Equal(retained, before) {
		t.Fatal("renewal changed previous rollback material")
	}
	cert, _ := os.ReadFile(second.CertificateFile)
	key, _ := os.ReadFile(second.KeyFile)
	if !validTLSPair(cert, key, spec.ServerName) {
		t.Fatal("renewal pair invalid")
	}
}
func TestTLSStageRejectsUnsafeSourceBeforePublication(t *testing.T) {
	for _, kind := range []string{"wrong_domain", "expired", "public_key", "mismatched_pair", "escaped_current", "file_symlink", "writable_parent"} {
		t.Run(kind, func(t *testing.T) {
			r, spec, root := tlsFixture(t)
			source := filepath.Join(root, "versions", "one")
			switch kind {
			case "wrong_domain":
				spec.ServerName = "wrong.invalid"
			case "expired":
				addTLSVersion(t, root, "expired", time.Now().Add(-time.Minute))
				if err := rotateTLSVersion(root, "expired"); err != nil {
					t.Fatal(err)
				}
			case "public_key":
				if err := os.Chmod(filepath.Join(source, "private.key"), 0644); err != nil {
					t.Fatal(err)
				}
			case "mismatched_pair":
				_, key := fixturePair(t, time.Now().Add(time.Hour))
				if err := os.WriteFile(filepath.Join(source, "private.key"), key, 0600); err != nil {
					t.Fatal(err)
				}
			case "escaped_current":
				if err := os.Remove(filepath.Join(root, "current")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), filepath.Join(root, "current")); err != nil {
					t.Fatal(err)
				}
			case "file_symlink":
				path := filepath.Join(source, "private.key")
				if err := os.Rename(path, path+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("private.key.real", path); err != nil {
					t.Fatal(err)
				}
			case "writable_parent":
				if err := os.Chmod(filepath.Join(root, "versions"), 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := r.Stage(spec); err == nil {
				t.Fatal("unsafe source published")
			}
			if _, err := os.Lstat(filepath.Join(r.base, "hysteria2")); !os.IsNotExist(err) {
				t.Fatal("rejected material touched runtime")
			}
		})
	}
}
func TestTLSStageRejectsCorruptPublishedVersion(t *testing.T) {
	r, spec, _ := tlsFixture(t)
	staged, err := r.Stage(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged.KeyFile, []byte("corrupt"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Stage(spec); err == nil {
		t.Fatal("corrupt runtime copy accepted")
	}
	key, _ := os.ReadFile(staged.KeyFile)
	if string(key) != "corrupt" {
		t.Fatal("corrupt published version overwritten")
	}
}
func TestTLSStageConcurrentRenewalReadsOneCompleteVersion(t *testing.T) {
	r, spec, root := tlsFixture(t)
	addTLSVersion(t, root, "two", time.Now().Add(2*time.Hour))
	var wg sync.WaitGroup
	wg.Add(1)
	failure := make(chan error, 1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			name := "one"
			if i%2 == 1 {
				name = "two"
			}
			if err := rotateTLSVersion(root, name); err != nil {
				failure <- err
				return
			}
		}
	}()
	for i := 0; i < 30; i++ {
		staged, err := r.Stage(spec)
		if err != nil {
			t.Fatal("concurrent renewal mixed or lost material", err)
		}
		cert, _ := os.ReadFile(staged.CertificateFile)
		key, _ := os.ReadFile(staged.KeyFile)
		if !validTLSPair(cert, key, spec.ServerName) {
			t.Fatal("mixed certificate/key pair")
		}
	}
	wg.Wait()
	select {
	case err := <-failure:
		t.Fatal(err)
	default:
	}
}
