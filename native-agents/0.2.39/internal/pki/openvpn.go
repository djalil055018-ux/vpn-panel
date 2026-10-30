package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"
)

type KeyPair struct{ Certificate, PrivateKey, Serial string }

func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err == nil {
		n.Add(n, big.NewInt(1))
	}
	return n, err
}
func encodePair(der []byte, key *ecdsa.PrivateKey, n *big.Int) (KeyPair, error) {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})), n.String()}, nil
}
func ParseCertificate(value string) (*x509.Certificate, error) {
	b, rest := pem.Decode([]byte(value))
	if b == nil || b.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" || strings.TrimSpace(value) != strings.TrimSpace(string(pem.EncodeToMemory(b))) {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(b.Bytes)
}
func parseKey(value string) (*ecdsa.PrivateKey, error) {
	b, rest := pem.Decode([]byte(value))
	if b == nil || b.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" || strings.TrimSpace(value) != strings.TrimSpace(string(pem.EncodeToMemory(b))) {
		return nil, errors.New("invalid private key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("ECDSA private key required")
	}
	return key, nil
}
func NewAuthority(name string, now time.Time) (KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	n, err := serial()
	if err != nil {
		return KeyPair{}, err
	}
	t := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
	if err != nil {
		return KeyPair{}, err
	}
	return encodePair(der, key, n)
}
func Issue(ca KeyPair, name string, server bool, now time.Time) (KeyPair, error) {
	issuer, err := ParseCertificate(ca.Certificate)
	if err != nil {
		return KeyPair{}, err
	}
	signer, err := parseKey(ca.PrivateKey)
	if err != nil {
		return KeyPair{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	n, err := serial()
	if err != nil {
		return KeyPair{}, err
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	expires := now.AddDate(1, 0, 0)
	if expires.After(issuer.NotAfter) {
		expires = issuer.NotAfter
	}
	t := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, t, issuer, &key.PublicKey, signer)
	if err != nil {
		return KeyPair{}, err
	}
	return encodePair(der, key, n)
}
func TLSCryptKey() (string, error) {
	b := make([]byte, 256)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	hexkey := hex.EncodeToString(b)
	var out strings.Builder
	out.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(hexkey); i += 32 {
		out.WriteString(hexkey[i:i+32] + "\n")
	}
	out.WriteString("-----END OpenVPN Static key V1-----\n")
	return out.String(), nil
}
func SignCRL(ca KeyPair, revoked []string, now time.Time) (string, error) {
	issuer, err := ParseCertificate(ca.Certificate)
	if err != nil {
		return "", err
	}
	signer, err := parseKey(ca.PrivateKey)
	if err != nil {
		return "", err
	}
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, value := range revoked {
		n, ok := new(big.Int).SetString(value, 10)
		if !ok || n.Sign() <= 0 {
			return "", errors.New("invalid revoked serial")
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: n, RevocationTime: now.Add(-time.Minute), ReasonCode: 6})
	}
	t := &x509.RevocationList{Number: big.NewInt(now.UnixNano()), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.AddDate(0, 1, 0), RevokedCertificateEntries: entries}
	der, err := x509.CreateRevocationList(rand.Reader, t, issuer, signer)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}

func ValidatePair(caPEM, certPEM, keyPEM, name string, server bool, now time.Time) error {
	ca, err := ParseCertificate(caPEM)
	if err != nil {
		return err
	}
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return err
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil || cert.Subject.CommonName != name || !public.Equal(&key.PublicKey) {
		return errors.New("certificate identity or key mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}
