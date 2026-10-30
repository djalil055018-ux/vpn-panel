package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/pki"
)

func openVPNFixture(t *testing.T) (model.ServiceSpec, pki.KeyPair, pki.KeyPair) {
	t.Helper()
	now := time.Now().UTC()
	id := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	clientID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	ca, err := pki.NewAuthority("VPN test authority", now)
	if err != nil {
		t.Fatal(err)
	}
	server, err := pki.Issue(ca, "server-"+id, true, now)
	if err != nil {
		t.Fatal(err)
	}
	client, err := pki.Issue(ca, "client-"+clientID, false, now)
	if err != nil {
		t.Fatal(err)
	}
	crypt, err := pki.TLSCryptKey()
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pki.SignCRL(ca, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	return model.ServiceSpec{ID: id, Protocol: "openvpn", Listen: "0.0.0.0", Port: 18449, Transport: "udp", Security: "tls", OpenVPN: &model.OpenVPNSpec{CACertificate: ca.Certificate, ServerCertificate: server.Certificate, ServerPrivateKey: server.PrivateKey, TLSCryptKey: crypt, CRL: crl}, Clients: []model.ClientSpec{{ID: clientID, StatsKey: clientID}}}, ca, client
}
func TestOpenVPNPKIAndConfig(t *testing.T) {
	s, _, client := openVPNFixture(t)
	now := time.Now().UTC()
	config, err := CompileOpenVPN(s, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"ccd-exclusive", "verify-client-cert require", "remote-cert-tls client", "tls-version-min 1.2", "allow-compression no", "<crl-verify>"} {
		if !strings.Contains(string(config), required) {
			t.Fatal("missing server security directive")
		}
	}
	address, port := "vpn.example", 1194
	service := model.VPNService{ID: s.ID, Protocol: "openvpn", Transport: "udp", PublicAddress: &address, PublicPort: &port}
	profile, err := OpenVPNProfile(service, s.OpenVPN.CACertificate, client.Certificate, client.PrivateKey, s.OpenVPN.TLSCryptKey, s.Clients[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "verify-x509-name server-"+s.ID+" name") {
		t.Fatal("server name is not pinned")
	}
	address = "vpn.example\nscript-security 3"
	if _, err = OpenVPNProfile(service, s.OpenVPN.CACertificate, client.Certificate, client.PrivateKey, s.OpenVPN.TLSCryptKey, s.Clients[0].ID, now); err == nil {
		t.Fatal("configuration injection accepted")
	}
	s.OpenVPN.ServerPrivateKey = "</key>\nscript-security 3\n" + s.OpenVPN.ServerPrivateKey
	if _, err = CompileOpenVPN(s, now); err == nil {
		t.Fatal("PEM prefix injection accepted")
	}
}

func TestOpenVPNTransportRegeneratesServerAndClientProfiles(t *testing.T) {
	s, _, client := openVPNFixture(t)
	now := time.Now().UTC()
	address, port := "vpn.example", 1194

	for _, tc := range []struct {
		transport, serverDirective, clientDirective string
	}{
		{transport: "udp", serverDirective: "proto udp", clientDirective: "proto udp"},
		{transport: "tcp", serverDirective: "proto tcp-server", clientDirective: "proto tcp-client"},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			s.Transport = tc.transport
			serverConfig, err := CompileOpenVPN(s, now)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(serverConfig), tc.serverDirective+"\n") {
				t.Fatalf("server configuration lacks %q", tc.serverDirective)
			}

			service := model.VPNService{ID: s.ID, Protocol: "openvpn", Transport: tc.transport, PublicAddress: &address, PublicPort: &port}
			profile, err := OpenVPNProfile(service, s.OpenVPN.CACertificate, client.Certificate, client.PrivateKey, s.OpenVPN.TLSCryptKey, s.Clients[0].ID, now)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(profile, tc.clientDirective+"\n") {
				t.Fatalf("client profile lacks %q", tc.clientDirective)
			}
		})
	}
}

// Produces disposable artifacts for a separate Docker-native CLI test.
func TestOpenVPNNativeArtifacts(t *testing.T) {
	dir := os.Getenv("VPN_TEST_OPENVPN_ARTIFACTS")
	if dir == "" {
		t.Skip("isolated artifacts directory required")
	}
	if !filepath.IsAbs(dir) || !strings.Contains(dir, "vpn-platform-candidates") {
		t.Fatal("refusing non-candidate directory")
	}
	s, ca, client := openVPNFixture(t)
	now := time.Now().UTC()
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "ccd"), 0700); err != nil {
		t.Fatal(err)
	}
	b, err := CompileOpenVPN(s, now)
	if err != nil {
		t.Fatal(err)
	}
	write("server.conf", b)
	write("ccd/client-"+s.Clients[0].ID, []byte("ifconfig-push 10.77.0.2 255.255.255.0\n"))
	address, port := "127.0.0.1", s.Port
	profile, err := OpenVPNProfile(model.VPNService{ID: s.ID, Protocol: "openvpn", Transport: s.Transport, PublicAddress: &address, PublicPort: &port}, ca.Certificate, client.Certificate, client.PrivateKey, s.OpenVPN.TLSCryptKey, s.Clients[0].ID, now)
	if err != nil {
		t.Fatal(err)
	}
	write("client.ovpn", []byte(profile))
	s.OpenVPN.CRL, err = pki.SignCRL(ca, []string{client.Serial}, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err = CompileOpenVPN(s, now)
	if err != nil {
		t.Fatal(err)
	}
	write("server-revoked.conf", b)
}
