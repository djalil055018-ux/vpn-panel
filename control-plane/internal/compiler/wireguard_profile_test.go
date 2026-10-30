package compiler

import (
	"encoding/base64"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

func TestWireGuardProfileValidation(t *testing.T) {
	private := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	public, _ := model.WireGuardPublicKey(private)
	profile, err := WireGuardProfile(private, public, private, "10.66.0.2/32", "2001:db8::1", 51820)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"Endpoint = [2001:db8::1]:51820", "Address = 10.66.0.2/32, fd66::a42:2/128", "AllowedIPs = 0.0.0.0/0, ::/0"} {
		if !strings.Contains(profile, part) {
			t.Fatal("profile field missing")
		}
	}
	for _, host := range []string{"host\nPostUp = malicious", "host\r\n[Peer]", "host with spaces", "bad:port", "[2001:db8::1]"} {
		if _, err = WireGuardProfile(private, public, private, "10.66.0.2/32", host, 51820); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	for _, address := range []string{"0.0.0.0/0", "10.66.0.2/24", "10.66.0.2/32\nDNS = bad", "8.8.8.8/32"} {
		if _, err = WireGuardProfile(private, public, private, address, "host.example", 51820); err == nil {
			t.Fatal("unsafe address accepted")
		}
	}
}
