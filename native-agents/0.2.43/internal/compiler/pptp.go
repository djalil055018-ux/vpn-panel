package compiler

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"vpn-platform/internal/model"
)

var pptpID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var pptpSecret = regexp.MustCompile(`^[a-f0-9]{64}$`)
var pptpEndpoint = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func PPTPProfile(address, username, password string) (string, error) {
	if !pptpEndpoint.MatchString(address) || len(address) > 253 || strings.HasPrefix(address, "-") || !pptpID.MatchString(username) || !pptpSecret.MatchString(password) {
		return "", errors.New("invalid PPTP connection")
	}
	return fmt.Sprintf("PPTP — legacy compatibility / устаревший протокол\n\nServer: %s\nPort: 1723/TCP + GRE (IP protocol 47)\nUsername: %s\nPassword: %s\nAuthentication: MS-CHAPv2 only\nEncryption: MPPE 128-bit required\n\nPPTP has known security weaknesses. Prefer WireGuard or OpenVPN when supported.\nIPv4 only: IPv6 is not carried by this tunnel. Configure the client to block IPv6 outside the tunnel.\nWindows: add a VPN connection, choose PPTP and username/password; require encryption and MS-CHAPv2 in its security settings.\nThis text is a credential sheet, not an automatically imported VPN profile. Keep it private.\n", address, username, password), nil
}

func ValidatePPTPService(s model.ServiceSpec) error {
	ip, err := netip.ParseAddr(s.Listen)
	if err != nil || !ip.Is4() || !pptpID.MatchString(s.ID) || s.Protocol != "pptp" || s.Transport != "tcp,gre" || s.Security != "mppe" || s.Port != 1723 || s.OpenVPN != nil || s.WireGuard != nil || s.Shadowsocks != nil || s.TLS != nil || s.Reality != nil || len(s.Clients) > 252 {
		return errors.New("invalid PPTP service: IPv4, TCP1723/GRE and MPPE are required")
	}
	seenID, seenIP := map[string]bool{}, map[string]bool{}
	for _, c := range s.Clients {
		if !pptpID.MatchString(c.ID) || c.ID != c.StatsKey || seenID[c.ID] || c.PPTP == nil || c.WireGuard != nil || !pptpSecret.MatchString(c.PPTP.Password) {
			return errors.New("invalid PPTP client identity or credential")
		}
		ip, err := netip.ParseAddr(c.PPTP.Address)
		if err != nil || !ip.Is4() || !netip.MustParsePrefix("10.78.0.0/24").Contains(ip) || ip.As4()[3] < 2 || ip.As4()[3] > 253 || seenIP[c.PPTP.Address] {
			return errors.New("invalid or duplicate PPTP client address")
		}
		seenID[c.ID], seenIP[c.PPTP.Address] = true, true
	}
	return nil
}

// Only a root-owned private working directory and fixed hook paths are used.
// Service names, caller paths and arbitrary options cannot become directives.
func CompilePPTP(s model.ServiceSpec, cliPassword string) (config, secrets []byte, err error) {
	if err = ValidatePPTPService(s); err != nil {
		return
	}
	if !pptpSecret.MatchString(cliPassword) {
		err = errors.New("invalid PPTP local control credential")
		return
	}
	config = []byte(fmt.Sprintf(`[modules]
path=/opt/vpn-platform-pptp/lib/accel-ppp
log_file
connlimit
chap-secrets
pptp
auth_mschap_v2
pppd_compat

[core]
log-error=core.log
thread-count=2

[common]
single-session=deny
sid-source=urandom
sid-case=lower
max-sessions=252
max-starting=32

[ppp]
verbose=0
min-mtu=1280
mtu=1400
mru=1400
mppe=require
ipv4=require
ipv6=deny
lcp-echo-interval=20
lcp-echo-timeout=60
unit-cache=0

[pptp]
bind=%s
port=1723
mppe=require
echo-interval=30
verbose=0
ifname=vppptp%%d

[auth]
timeout=5
max-failure=3

[client-ip-range]
0.0.0.0/0

[chap-secrets]
chap-secrets=chap-secrets
gw-ip-address=10.78.0.1/24

[dns]
dns1=1.1.1.1
dns2=9.9.9.9

[pppd-compat]
ip-pre-up=./ip-pre-up
ip-down=./ip-down
fork-limit=16
verbose=0

[connlimit]
limit=10/min
burst=5
timeout=60

[log]
log-file=accel.log
level=1

[cli]
tcp=127.0.0.1:2002
password=%s
verbose=0
`, s.Listen, cliPassword))
	var b strings.Builder
	for _, c := range s.Clients {
		fmt.Fprintf(&b, "%s * %s %s\n", c.ID, c.PPTP.Password, c.PPTP.Address)
	}
	secrets = []byte(b.String())
	return
}
