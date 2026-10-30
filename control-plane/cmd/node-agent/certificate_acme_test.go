package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/certificate"
	"vpn-platform/internal/model"
)

func certificateFixture(t *testing.T, domain string, expired bool) *certificate.Resource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(time.Hour)
	if expired {
		end = time.Now().Add(-time.Minute)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &certificate.Resource{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
}

func TestCertificateInstallPreservesCurrentOnInvalidMaterial(t *testing.T) {
	base := t.TempDir()
	id := "00000000-0000-0000-0000-000000000001"
	domain := "vpn.example.test"
	valid := certificateFixture(t, domain, false)
	if _, err := installCertificateVersion(base, id, domain, valid); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(base, "certificates", id, "current")
	before, err := os.Readlink(current)
	if err != nil {
		t.Fatal(err)
	}
	other := certificateFixture(t, domain, false)
	for _, tc := range []struct {
		name     string
		resource *certificate.Resource
		domain   string
	}{
		{"mismatched key", &certificate.Resource{Certificate: valid.Certificate, PrivateKey: other.PrivateKey}, domain},
		{"wrong hostname", valid, "other.example.test"},
		{"expired", certificateFixture(t, domain, true), domain},
		{"incomplete", &certificate.Resource{Certificate: valid.Certificate}, domain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := installCertificateVersion(base, id, tc.domain, tc.resource); err == nil {
				t.Fatal("invalid certificate accepted")
			}
			after, err := os.Readlink(current)
			if err != nil || after != before {
				t.Fatal("current certificate changed after rejected install")
			}
		})
	}
	info, err := os.Stat(filepath.Join(current, "private.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions are not 0600")
	}
	if _, err := installCertificateVersion(base, id, domain, other); err != nil {
		t.Fatal(err)
	}
	after, err := os.Readlink(current)
	if err != nil || after == before {
		t.Fatal("renewal did not select a new immutable version")
	}
	if _, err := os.Stat(filepath.Join(base, "certificates", id, before, "private.key")); err != nil {
		t.Fatal("prior certificate version lost")
	}
}

func TestRemoveCertificateMaterialRemovesOnlyNamedCertificate(t *testing.T) {
	base := t.TempDir()
	id := "00000000-0000-0000-0000-000000000001"
	other := "00000000-0000-0000-0000-000000000002"
	for _, name := range []string{id, other} {
		path := filepath.Join(base, "certificates", name, "versions", "one")
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "private.key"), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeCertificateMaterial(base, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "certificates", id)); !os.IsNotExist(err) {
		t.Fatal("requested certificate remains")
	}
	if _, err := os.Stat(filepath.Join(base, "certificates", other, "versions", "one", "private.key")); err != nil {
		t.Fatal("unrelated certificate was changed", err)
	}
}

func TestRemoveCertificateMaterialRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	id := "00000000-0000-0000-0000-000000000001"
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "certificates")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := removeCertificateMaterial(base, id); err == nil {
		t.Fatal("symlinked certificate root accepted")
	}
}

func TestObtainCertificateDeleteDoesNotRequireRuntimeRefresh(t *testing.T) {
	base := t.TempDir()
	id := "00000000-0000-0000-0000-000000000001"
	path := filepath.Join(base, "certificates", id, "versions", "one")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "private.key"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	grant := model.CertificateJobGrant{JobID: "00000000-0000-0000-0000-000000000002", CertificateID: id, Operation: "delete", CertificateRef: "certificates/" + id, LeaseToken: "test-lease"}
	report, err := obtainCertificateWithRuntime(t.Context(), base, grant, nil)
	if err != nil || !report.Success || report.JobID != grant.JobID || report.CertificateID != grant.CertificateID || report.Issuer != "" || report.FingerprintSHA256 != "" {
		t.Fatal("certificate delete job failed or returned certificate metadata", err)
	}
	if _, err := os.Stat(filepath.Join(base, "certificates", id)); !os.IsNotExist(err) {
		t.Fatal("certificate files remain")
	}
}

func TestCertificateIDAndEnvironmentValidation(t *testing.T) {
	for _, id := range []string{"", "../outside", "00000000-0000-0000-0000-00000000000g"} {
		if validCertificateID(id) {
			t.Fatal("invalid certificate ID accepted")
		}
	}
	if !validCertificateID("00000000-0000-0000-0000-000000000001") {
		t.Fatal("valid certificate ID rejected")
	}
	staging, e1 := certificateCAURL("staging")
	production, e2 := certificateCAURL("production")
	if e1 != nil || e2 != nil || staging == production {
		t.Fatal("ACME environment selection invalid")
	}
	if _, err := certificateCAURL("unknown"); err == nil {
		t.Fatal("unknown CA environment accepted")
	}
}
