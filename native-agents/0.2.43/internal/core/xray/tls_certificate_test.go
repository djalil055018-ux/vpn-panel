package xray

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

const tlsTestID = "11111111-1111-4111-8111-111111111111"

func writeTLSFixture(t *testing.T, root, domain string, expiry time.Time) {
	t.Helper()
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"fullchain.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "private.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func tlsFixtureState() model.DesiredState {
	return model.DesiredState{Services: []model.ServiceSpec{{ID: tlsTestID, Protocol: "vless", Listen: "127.0.0.1", Port: 8443, Transport: "tcp", Security: "tls", TLS: &model.TLSSpec{CertificateID: tlsTestID, ServerName: "test.example"}}}}
}

func TestTLSCertificateResolvedLocallyAndCompilerUsesReloadableFiles(t *testing.T) {
	d := New(t.TempDir())
	root := filepath.Join(d.BaseDir, "certificates", tlsTestID)
	version := filepath.Join(root, "versions", "one")
	writeTLSFixture(t, version, "test.example", time.Now().Add(time.Hour))
	if err := os.Symlink("versions/one", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	state := tlsFixtureState()
	resolved, err := d.resolveTLSCertificates(state)
	if err != nil {
		t.Fatal(err)
	}
	if state.Services[0].TLS.KeyFile != "" {
		t.Fatal("input mutated")
	}
	raw, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), d.BaseDir) || strings.Contains(string(raw), "private.key") {
		t.Fatal("local paths serialized")
	}
	config, err := compiler.CompileXray(resolved)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(config, &value); err != nil {
		t.Fatal(err)
	}
	in := value["inbounds"].([]any)[0].(map[string]any)
	stream := in["streamSettings"].(map[string]any)
	if stream["security"] != "tls" {
		t.Fatal("wrong security")
	}
	cert := stream["tlsSettings"].(map[string]any)["certificates"].([]any)[0].(map[string]any)
	if cert["oneTimeLoading"] != false || cert["keyFile"] != filepath.Join(root, "current", "private.key") {
		t.Fatal("TLS reload path mismatch")
	}
}

func TestTLSCertificateRejectsInvalidMaterialBeforeCompile(t *testing.T) {
	for _, name := range []string{"missing", "expired", "hostname", "permissions", "escape", "identity", "mismatch"} {
		t.Run(name, func(t *testing.T) {
			d := New(t.TempDir())
			state := tlsFixtureState()
			root := filepath.Join(d.BaseDir, "certificates", tlsTestID, "current")
			domain := "test.example"
			expiry := time.Now().Add(time.Hour)
			if name == "expired" {
				expiry = time.Now().Add(-time.Minute)
			}
			if name == "hostname" {
				domain = "other.example"
			}
			if name != "missing" {
				writeTLSFixture(t, root, domain, expiry)
			}
			if name == "permissions" {
				if err := os.Chmod(filepath.Join(root, "private.key"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if name == "identity" {
				state.Services[0].TLS.CertificateID = "../../etc"
			}
			if name == "escape" {
				p := filepath.Join(root, "private.key")
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(d.BaseDir, "outside-key")
				if err = os.WriteFile(outside, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(outside, p); err != nil {
					t.Fatal(err)
				}
			}
			if name == "mismatch" {
				other := filepath.Join(d.BaseDir, "other")
				writeTLSFixture(t, other, domain, expiry)
				raw, err := os.ReadFile(filepath.Join(other, "private.key"))
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(root, "private.key"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := d.resolveTLSCertificates(state); err == nil {
				t.Fatal("invalid TLS material accepted")
			}
		})
	}
}

func TestTLSRuntimePublicationIsPrivateAndAtomic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("runtime ownership test needs root")
	}
	d := New(t.TempDir())
	source := filepath.Join(d.BaseDir, "certificates", tlsTestID, "current")
	writeTLSFixture(t, source, "test.example", time.Now().Add(time.Hour))
	resolved, err := d.resolveTLSCertificates(tlsFixtureState())
	if err != nil {
		t.Fatal(err)
	}
	spec, err := d.publishTLSRuntime(*resolved.Services[0].TLS, os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(spec.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatal("runtime key permission mismatch")
	}
	original, err := os.Stat(filepath.Join(source, "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	if original.Mode().Perm() != 0600 {
		t.Fatal("ACME original permissions changed")
	}
	oldTarget, err := filepath.EvalSymlinks(spec.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, "private.key"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = d.publishTLSRuntime(*resolved.Services[0].TLS, os.Getgid()); err == nil {
		t.Fatal("invalid replacement published")
	}
	still, err := filepath.EvalSymlinks(spec.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if still != oldTarget {
		t.Fatal("invalid replacement changed current")
	}
	writeTLSFixture(t, source, "test.example", time.Now().Add(2*time.Hour))
	if _, err = d.publishTLSRuntime(*resolved.Services[0].TLS, os.Getgid()); err != nil {
		t.Fatal(err)
	}
	newTarget, err := filepath.EvalSymlinks(spec.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if newTarget == oldTarget {
		t.Fatal("renewal did not advance runtime")
	}
	if _, err = os.Stat(oldTarget); err != nil {
		t.Fatal("previous certificate version lost")
	}
}
