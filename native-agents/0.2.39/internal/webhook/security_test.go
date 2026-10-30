package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestWebhookEncryption(t *testing.T) {
	master := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	a, err := Encrypt(master, "endpoint-a", "private-secret")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encrypt(master, "endpoint-a", "private-secret")
	if err != nil || a == b {
		t.Fatal("nonce not random")
	}
	plain, err := Decrypt(master, "endpoint-a", a)
	if err != nil || plain != "private-secret" {
		t.Fatal("roundtrip failed")
	}
	if _, err = Decrypt(master, "endpoint-b", a); err == nil {
		t.Fatal("endpoint substitution accepted")
	}
	if _, err = Encrypt("bad", "endpoint-a", "secret"); err == nil {
		t.Fatal("bad master accepted")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(a)
	raw[len(raw)-1] ^= 1
	if _, err = Decrypt(master, "endpoint-a", base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
func TestWebhookDestinationValidation(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.1.1.1", "169.254.169.254", "100.64.1.1", "192.168.1.1", "172.16.0.1", "198.18.1.1", "192.0.2.1", "224.0.0.1", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "64:ff9b::7f00:1", "2002:7f00:1::", "2001:db8::1"} {
		if PublicAddress(netip.MustParseAddr(value)) {
			t.Fatal("nonpublic address accepted")
		}
	}
	for _, value := range []string{"8.8.4.4", "8.8.8.8", "2606:4700:4700::1111"} {
		if !PublicAddress(netip.MustParseAddr(value)) {
			t.Fatal("public address rejected")
		}
	}
	for _, value := range []string{"http://example.org/hook", "https://localhost/hook", "https://127.0.0.1/hook", "https://[::1]/hook", "https://user:pass@example.org/hook", "https://example.org:8443/hook", "https://example.org/hook?secret=value", "https://example.org/hook#fragment", "https://example.org\\evil"} {
		if ValidateURL(value) {
			t.Fatal("invalid destination accepted")
		}
	}
	if !ValidateURL("https://panel.example.com/callback") {
		t.Fatal("valid HTTPS rejected")
	}
	if conn, err := safeDial(context.Background(), "tcp", "127.0.0.1:443"); err == nil || conn != nil {
		t.Fatal("private dial accepted")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestWebhookSignedPayloadAndRedirectPolicy(t *testing.T) {
	body := []byte(`{"id":"event-a"}`)
	secret := "signing-secret"
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(r.Header.Get("X-VPN-Timestamp") + "."))
		h.Write(raw)
		if string(raw) != string(body) || r.Header.Get("X-VPN-Signature") != hex.EncodeToString(h.Sum(nil)) || r.Header.Get("X-VPN-Event-ID") != "event-a" {
			t.Fatal("signature or identity mismatch")
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if code, category := Send(context.Background(), client, "https://example.org/hook", secret, "event-a", "delivery-a", body); code != 204 || category != "" {
		t.Fatal("delivery failed")
	}
	production := NewHTTPClient()
	defer production.CloseIdleConnections()
	if production.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects allowed")
	}
	if production.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("environment proxy enabled")
	}
}
