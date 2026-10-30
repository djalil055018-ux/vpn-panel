package compiler

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/pki"
)

var openVPNID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var openVPNEndpoint = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

const openVPNTLSBegin = "-----BEGIN OpenVPN Static key V1-----\n"
const openVPNTLSEnd = "-----END OpenVPN Static key V1-----\n"

func validateTLSCrypt(value string) bool {
	if !strings.HasPrefix(value, openVPNTLSBegin) || !strings.HasSuffix(value, openVPNTLSEnd) {
		return false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(value, openVPNTLSBegin), openVPNTLSEnd)
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) != 16 {
		return false
	}
	for _, line := range lines {
		if len(line) != 32 {
			return false
		}
		if _, err := hex.DecodeString(line); err != nil {
			return false
		}
	}
	return true
}
func ValidateOpenVPNService(s model.ServiceSpec, now time.Time) error {
	if len(s.Clients) > 252 {
		return errors.New("OpenVPN supports at most 252 active clients per service")
	}
	if !openVPNID.MatchString(s.ID) || s.Protocol != "openvpn" || (s.Transport != "udp" && s.Transport != "tcp") || s.Security != "tls" || s.OpenVPN == nil || net.ParseIP(s.Listen) == nil || s.Port < 1 || s.Port > 65535 {
		return errors.New("invalid OpenVPN service")
	}
	p := s.OpenVPN
	if err := pki.ValidatePair(p.CACertificate, p.ServerCertificate, p.ServerPrivateKey, "server-"+s.ID, true, now); err != nil {
		return err
	}
	if !validateTLSCrypt(p.TLSCryptKey) {
		return errors.New("invalid OpenVPN tls-crypt key")
	}
	b, rest := pem.Decode([]byte(p.CRL))
	if b == nil || b.Type != "X509 CRL" || strings.TrimSpace(string(rest)) != "" || strings.TrimSpace(p.CRL) != strings.TrimSpace(string(pem.EncodeToMemory(b))) {
		return errors.New("invalid OpenVPN CRL")
	}
	crl, err := x509.ParseRevocationList(b.Bytes)
	if err != nil {
		return err
	}
	ca, _ := pki.ParseCertificate(p.CACertificate)
	if crl.CheckSignatureFrom(ca) != nil || now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
		return errors.New("OpenVPN CRL expired or invalid")
	}
	seen := map[string]bool{}
	for _, c := range s.Clients {
		if !openVPNID.MatchString(c.StatsKey) || c.ID != c.StatsKey || seen[c.ID] {
			return errors.New("invalid OpenVPN client identity")
		}
		seen[c.ID] = true
	}
	return nil
}

// Relative runtime paths are fixed by the driver. No commands or paths supplied
// by an API caller can become OpenVPN directives.
func CompileOpenVPN(s model.ServiceSpec, now time.Time) ([]byte, error) {
	if err := ValidateOpenVPNService(s, now); err != nil {
		return nil, err
	}
	proto := "udp"
	if s.Transport == "tcp" {
		proto = "tcp-server"
	}
	p := s.OpenVPN
	config := fmt.Sprintf(`local %s
port %d
proto %s
dev vpnovpn0
dev-type tun
topology subnet
server 10.77.0.0 255.255.255.0
server-ipv6 fd77::/64
push "redirect-gateway def1 ipv6"
push "dhcp-option DNS 1.1.1.1"
block-ipv6
push "block-ipv6"
client-config-dir ccd
ccd-exclusive
verify-client-cert require
remote-cert-tls client
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
allow-compression no
dh none
keepalive 10 60
persist-key
persist-tun
disable-dco
script-security 1
status status.log 1
status-version 3
verb 3
<ca>
%s</ca>
<cert>
%s</cert>
<key>
%s</key>
<tls-crypt>
%s</tls-crypt>
<crl-verify>
%s</crl-verify>
`, s.Listen, s.Port, proto, p.CACertificate, p.ServerCertificate, p.ServerPrivateKey, p.TLSCryptKey, p.CRL)
	return []byte(config), nil
}

func OpenVPNProfile(s model.VPNService, ca, cert, key, tlsCrypt string, clientID string, now time.Time) (string, error) {
	if s.Protocol != "openvpn" || (s.Transport != "udp" && s.Transport != "tcp") || !openVPNID.MatchString(s.ID) || !openVPNID.MatchString(clientID) || s.PublicAddress == nil || s.PublicPort == nil || *s.PublicPort < 1 || *s.PublicPort > 65535 || (!openVPNEndpoint.MatchString(*s.PublicAddress) && net.ParseIP(*s.PublicAddress) == nil) || !validateTLSCrypt(tlsCrypt) {
		return "", errors.New("invalid OpenVPN profile")
	}
	if err := pki.ValidatePair(ca, cert, key, "client-"+clientID, false, now); err != nil {
		return "", err
	}
	proto := "udp"
	if s.Transport == "tcp" {
		proto = "tcp-client"
	}
	return fmt.Sprintf(`client
dev tun
proto %s
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server-%s name
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
allow-compression no
auth-nocache
verb 3
<ca>
%s</ca>
<cert>
%s</cert>
<key>
%s</key>
<tls-crypt>
%s</tls-crypt>
`, proto, *s.PublicAddress, *s.PublicPort, s.ID, ca, cert, key, tlsCrypt), nil
}
