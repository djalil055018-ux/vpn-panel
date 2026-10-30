// Package subscriptioncompat renders reviewed imported subscription profiles.
// It never decides account authorization; the caller supplies only currently
// authorized hosts and a current native credential.
package subscriptioncompat

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

var ErrProfile = errors.New("unsupported or invalid public subscription profile")
var credentialPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Options = map[string]any

// This intermediate form contains public transport metadata, without server
// keys or source users. Input protocol/transport credential fields are ignored;
// only Render's explicit current credential may appear in the output.
type Host struct {
	// Private fields are set only by the native store/allocator, never by JSON
	// from an imported profile. Shadowsocks uses its per-service client secret.
	NativeShadowsocksPassword string  `json:"-"`
	Automatic                 bool    `json:"-"`
	AutoRussiaDirect          bool    `json:"-"`
	Name                      string  `json:"finalRemark"`
	Address                   string  `json:"address"`
	Port                      int     `json:"port"`
	Protocol                  string  `json:"protocol"`
	Transport                 string  `json:"transport"`
	Security                  string  `json:"security"`
	ProtocolOptions           Options `json:"protocolOptions"`
	TransportOptions          Options `json:"transportOptions"`
	SecurityOptions           Options `json:"securityOptions"`
	Mux                       Options `json:"mux"`
	Stream                    struct {
		FinalMask Options `json:"finalMask"`
		Sockopt   Options `json:"sockopt"`
	} `json:"streamOverrides"`
	Client struct {
		Shuffle      bool    `json:"shuffleHost"`
		X25519       bool    `json:"mihomoX25519"`
		IPVersion    *string `json:"mihomoIpVersion"`
		Description  *string `json:"serverDescription"`
		XrayTemplate Options `json:"xrayJsonTemplate"`
		Mapper       Options `json:"mapper"`
	} `json:"clientOverrides"`
	Metadata struct {
		Hidden   bool     `json:"isHidden"`
		Disabled bool     `json:"isDisabled"`
		Excluded []string `json:"excludeFromSubscriptionTypes"`
	} `json:"metadata"`
}

func text(v any) string    { s, _ := v.(string); return s }
func truth(v any) bool     { b, _ := v.(bool); return b }
func object(v any) Options { m, _ := v.(map[string]any); return m }
func clone(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}
func copyObject(v Options) Options {
	if v == nil {
		return Options{}
	}
	return clone(v).(map[string]any)
}
func putText(out Options, key string, value any) {
	if s := text(value); s != "" {
		out[key] = s
	}
}
func valueOr(v any, fallback any) any {
	if v == nil {
		return fallback
	}
	return v
}
func skipped(h Host, format string) bool {
	if h.Metadata.Disabled || (h.Metadata.Hidden && format != "XRAY_BASE64" && format != "SINGBOX") {
		return true
	}
	for _, excluded := range h.Metadata.Excluded {
		if excluded == format {
			return true
		}
	}
	return false
}
func validHost(h Host) bool {
	if h.Name == "" || len(h.Name) > 4096 || !utf8.ValidString(h.Name) || strings.ContainsAny(h.Name, "\r\n\x00") || h.Address == "" || len(h.Address) > 253 ||
		strings.ContainsAny(h.Address, " \r\n\t\x00/@?#") || h.Port < 1 || h.Port > 65535 {
		return false
	}
	if strings.Contains(h.Address, ":") && net.ParseIP(h.Address) == nil {
		return false
	}
	if h.Client.Shuffle || h.Client.X25519 || h.Client.IPVersion != nil || h.Client.Description != nil || len(h.Client.XrayTemplate) > 0 || len(h.Client.Mapper) > 0 {
		return false
	}
	if h.Protocol == "shadowsocks" {
		parts := strings.Split(h.NativeShadowsocksPassword, ":")
		if h.Transport != "tcp,udp" || h.Security != "shadowsocks" || len(parts) != 2 || parts[0] == parts[1] {
			return false
		}
		for _, part := range parts {
			raw, err := base64.StdEncoding.DecodeString(part)
			if err != nil || len(raw) != 32 {
				return false
			}
		}
	} else if h.Protocol == "hysteria" {
		if h.Transport != "hysteria" || h.Security != "tls" {
			return false
		}
	} else if h.Protocol == "trojan" {
		if h.Transport != "tcp" || h.Security != "tls" || text(h.SecurityOptions["serverName"]) == "" {
			return false
		}
	} else if h.Protocol == "vless" {
		if h.Transport != "tcp" && h.Transport != "grpc" && h.Transport != "xhttp" && h.Transport != "ws" {
			return false
		}
		if h.Security != "reality" && h.Security != "tls" {
			return false
		}
		if text(h.ProtocolOptions["encryption"]) != "none" {
			return false
		}
		flow := text(h.ProtocolOptions["flow"])
		if flow != "" && flow != "xtls-rprx-vision" {
			return false
		}
		if flow != "" && h.Transport != "tcp" {
			return false
		}
	} else {
		return false
	}
	if h.Security == "reality" && (text(h.SecurityOptions["publicKey"]) == "" || text(h.SecurityOptions["serverName"]) == "") {
		return false
	}
	if h.Security == "reality" {
		key, err := base64.RawURLEncoding.DecodeString(text(h.SecurityOptions["publicKey"]))
		if err != nil || len(key) != 32 {
			return false
		}
	}
	// These features are absent from the reviewed source and have different
	// meanings across client formats. Never silently approximate them.
	for _, name := range []string{"pinnedPeerCertSha256", "verifyPeerCertByName", "echConfigList", "echForceQuery", "echSockopt", "cipherSuites", "mldsa65Verify"} {
		if v := h.SecurityOptions[name]; v != nil && v != "" {
			return false
		}
	}
	if len(object(h.Mux["smux"])) > 0 || len(object(h.TransportOptions["extra"])) > 0 || len(object(h.TransportOptions["header"])) > 0 {
		return false
	}
	if len(h.Stream.FinalMask) > 0 {
		quic := object(h.Stream.FinalMask["quicParams"])
		if len(h.Stream.FinalMask) != 1 || len(quic) != 2 || quic["congestion"] != "bbr" || quic["debug"] != false {
			return false
		}
	}
	return true
}

func DecodeHost(raw []byte) (Host, error) {
	var h Host
	if json.Unmarshal(raw, &h) != nil || !validHost(h) {
		return Host{}, ErrProfile
	}
	return h, nil
}

func ValidateHost(h Host) error {
	if !validHost(h) {
		return ErrProfile
	}
	return nil
}
