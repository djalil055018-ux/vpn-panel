package store

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

type importedTLSChain struct {
	leaf, intermediate, root *x509.Certificate
	fullchain                string
	roots                    *x509.CertPool
}

func importedTLSTestChain(t *testing.T, domain string, mutate func(*x509.Certificate)) importedTLSChain {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	issue := func(c, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		der, e := x509.CreateCertificate(rand.Reader, c, parent, pub, signer)
		if e != nil {
			t.Fatal(e)
		}
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		return cert
	}
	rk, ik, lk := key(), key(), key()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic TLS root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	root = issue(root, root, &rk.PublicKey, rk)
	middle := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic TLS intermediate"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: root.NotBefore, NotAfter: root.NotAfter}
	middle = issue(middle, root, &ik.PublicKey, rk)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 24 * time.Hour)}
	if mutate != nil {
		mutate(leaf)
	}
	leaf = issue(leaf, middle, &lk.PublicKey, ik)
	encode := func(c *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return importedTLSChain{leaf, middle, root, encode(leaf) + encode(middle), pool}
}

func TestVerifyImportedTLS(t *testing.T) {
	c := importedTLSTestChain(t, "import.example.test", nil)
	leaf, digest, e := verifyImportedTLS("import.example.test", "\n"+c.fullchain+"\n", c.roots, time.Now())
	if e != nil || !leaf.Equal(c.leaf) {
		t.Fatal("valid reviewed chain rejected")
	}
	h := sha256.New()
	h.Write(c.leaf.Raw)
	h.Write(c.intermediate.Raw)
	if digest != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("chain digest differs")
	}
	encode := func(cert *x509.Certificate) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	for name, material := range map[string]string{
		"empty": "", "prefix": "not a certificate\n" + c.fullchain, "tail": c.fullchain + "garbage",
		"private-key": c.fullchain + "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n",
		"wrong-order": encode(c.intermediate) + encode(c.leaf), "missing-intermediate": encode(c.leaf),
		"unrelated-tail": c.fullchain + encode(c.leaf), "too-many": strings.Repeat(encode(c.leaf), 9),
		"headers":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X-Private": "no"}, Bytes: c.leaf.Raw})) + encode(c.intermediate),
		"too-large": strings.Repeat(" ", 65537) + c.fullchain,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, e := verifyImportedTLS("import.example.test", material, c.roots, time.Now()); e == nil {
				t.Fatal("unsafe chain accepted")
			}
		})
	}
	for _, domain := range []string{"other.example.test", "IMPORT.example.test", "*.example.test", "localhost", "https://import.example.test", "import.example.test:443"} {
		if _, _, e := verifyImportedTLS(domain, c.fullchain, c.roots, time.Now()); e == nil {
			t.Fatal("invalid domain accepted")
		}
	}
	if _, _, e := verifyImportedTLS("import.example.test", c.fullchain, x509.NewCertPool(), time.Now()); e == nil {
		t.Fatal("untrusted chain accepted")
	}
	if _, _, e := verifyImportedTLS("import.example.test", c.fullchain, nil, time.Now()); e == nil {
		t.Fatal("synthetic test root trusted in production")
	}
	for name, mutate := range map[string]func(*x509.Certificate){
		"expired": func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-48 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		},
		"future":      func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		"CA-leaf":     func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign },
		"wrong-usage": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := importedTLSTestChain(t, "import.example.test", mutate)
			if _, _, e := verifyImportedTLS("import.example.test", bad.fullchain, bad.roots, time.Now()); e == nil {
				t.Fatal("invalid leaf accepted")
			}
		})
	}
}
