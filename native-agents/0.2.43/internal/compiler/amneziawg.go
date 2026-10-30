package compiler

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"vpn-platform/internal/model"
)

func validatedAWGService(s model.ServiceSpec) (model.ServiceSpec, string, error) {
	if s.Protocol != "amneziawg" || s.Transport != "udp" || s.Security != "amneziawg" || s.AmneziaWG == nil {
		return s, "", errors.New("AmneziaWG requires its own UDP runtime and version settings")
	}
	lines, e := s.AmneziaWG.ConfigLines()
	if e != nil {
		return s, "", e
	}
	plain := s
	plain.Protocol = "wireguard"
	plain.Security = "wireguard"
	plain.AmneziaWG = nil
	if _, e := CompileKernelWireGuard(plain); e != nil {
		return s, "", e
	}
	return plain, lines, nil
}

// CompileAmneziaWG returns input for the official awg setconf command, with no
// addresses, routing directives, shell hooks or executable owner-supplied text.
func CompileAmneziaWG(s model.ServiceSpec) ([]byte, error) {
	plain, lines, e := validatedAWGService(s)
	if e != nil {
		return nil, e
	}
	config, e := CompileKernelWireGuard(plain)
	if e != nil {
		return nil, e
	}
	return []byte(strings.Replace(string(config), "[Interface]\n", "[Interface]\n"+lines, 1)), nil
}

func AmneziaWGProfile(privateKey, serverPublic, presharedKey, address, endpoint string, port int, spec model.AmneziaWGSpec) (string, error) {
	lines, e := spec.ConfigLines()
	if e != nil {
		return "", e
	}
	profile, e := WireGuardProfile(privateKey, serverPublic, presharedKey, address, endpoint, port)
	if e != nil {
		return "", e
	}
	profile = strings.Replace(profile, "MTU = 1420\n", "MTU = 1280\n", 1)
	return "# PAUK AmneziaWG " + spec.Version + "\n" + strings.Replace(profile, "[Interface]\n", "[Interface]\n"+lines, 1), nil
}

// AmneziaWGUAPI compiles the same validated settings directly to the official
// userspace runtime control protocol. This avoids shelling out or parsing a
// wg-quick file on the node. Never log the returned bytes.
func AmneziaWGUAPI(s model.ServiceSpec) ([]byte, error) {
	plain, lines, e := validatedAWGService(s)
	if e != nil {
		return nil, e
	}
	var b strings.Builder
	hexKey := func(v string) string {
		data, _ := base64.StdEncoding.Strict().DecodeString(v)
		return hex.EncodeToString(data)
	}
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", hexKey(plain.WireGuard.PrivateKey), s.Port)
	keys := map[string]string{"HeaderProtectionKey": "header_protection_key", "ContentPaddingAddition": "content_padding_addition", "RekeyAfterTime": "rekey_after_time", "RekeyTimeout": "rekey_timeout", "RejectAfterTime": "reject_after_time", "KeepaliveTimeout": "keepalive_timeout", "MaxHandshakeAttempts": "max_handshake_attempts", "RandomTrailers": "random_trailers", "DisableCookies": "disable_cookies"}
	for _, line := range strings.Split(strings.TrimSpace(lines), "\n") {
		key, value, _ := strings.Cut(line, " = ")
		name, ok := keys[key]
		if !ok {
			name = strings.ToLower(key)
		}
		if key == "HeaderProtectionKey" {
			value = hexKey(value)
		}
		if key == "RandomTrailers" || key == "DisableCookies" {
			if value == "1" {
				value = "true"
			} else {
				value = "false"
			}
		}
		fmt.Fprintf(&b, "%s=%s\n", name, value)
	}
	peers := append([]model.ClientSpec(nil), plain.Clients...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].WireGuard.PublicKey < peers[j].WireGuard.PublicKey })
	for _, c := range peers {
		p := c.WireGuard
		fmt.Fprintf(&b, "public_key=%s\npreshared_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s\nallowed_ip=%s\n", hexKey(p.PublicKey), hexKey(p.PresharedKey), p.Address, model.WireGuardIPv6Address(p.Address))
	}
	return []byte(b.String()), nil
}
