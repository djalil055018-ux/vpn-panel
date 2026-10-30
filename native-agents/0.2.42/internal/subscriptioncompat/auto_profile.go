package subscriptioncompat

import (
	"strings"
	"vpn-platform/internal/autoprofile"
)

// Candidates contain only services already authorized by the subscription's
// database snapshot. Neither a user agent nor a requested format grants access.
type AutoCandidate struct {
	HostIndex         int
	NodeID, ServiceID string
}
type AutoProfile struct {
	Enabled      bool
	Name         string
	RussiaDirect bool
	ClientKey    string
	Candidates   []AutoCandidate
}

// WithAuto adds an independent profile and leaves every manual host intact.
// Assignment is recomputed on subscription refresh, not during a TCP session.
func WithAuto(hosts []Host, profile AutoProfile, format string) ([]Host, bool) {
	if !profile.Enabled || profile.Name == "" {
		return hosts, false
	}
	endpoints := []autoprofile.Endpoint{}
	indices := map[string]int{}
	for _, c := range profile.Candidates {
		if c.HostIndex < 0 || c.HostIndex >= len(hosts) {
			continue
		}
		h := hosts[c.HostIndex]
		if !autoCompatible(h, format) {
			continue
		}
		endpoints = append(endpoints, autoprofile.Endpoint{NodeID: c.NodeID, ServiceID: c.ServiceID, Healthy: true, Preference: autoPreference(h)})
		indices[c.ServiceID] = c.HostIndex
	}
	selected, ok := autoprofile.Select(profile.ClientKey, endpoints)
	if !ok {
		return hosts, false
	}
	h := hosts[indices[selected.ServiceID]]
	h.Name = profile.Name
	h.AutoRussiaDirect = profile.RussiaDirect
	h.Automatic = true
	result := make([]Host, 0, len(hosts)+1)
	result = append(result, h)
	return append(result, hosts...), true
}

func autoCompatible(h Host, format string) bool {
	if !validHost(h) || skipped(h, format) || h.Metadata.Hidden {
		return false
	}
	switch format {
	case "XRAY_BASE64", "XRAY_JSON":
		return true
	case "SINGBOX":
		return h.Transport != "xhttp" && !truth(h.TransportOptions["multiMode"]) && text(h.TransportOptions["authority"]) == ""
	case "MIHOMO":
		return !truth(h.TransportOptions["multiMode"]) && text(h.TransportOptions["authority"]) == ""
	case "STASH":
		return h.Transport != "xhttp" && !truth(h.TransportOptions["multiMode"]) && text(h.TransportOptions["authority"]) == ""
	case "CLASH":
		return h.Protocol == "trojan"
	}
	return false
}

func autoPreference(h Host) int {
	// TCP avoids dependence on the mobile network permitting UDP. Every node
	// still receives one equal allocation slot regardless of transport count.
	switch {
	case h.Protocol == "vless" && h.Transport == "tcp":
		return 0
	case h.Protocol == "trojan":
		return 1
	case h.Protocol == "vless" && h.Transport == "ws":
		return 2
	case h.Protocol == "vless" && h.Transport == "xhttp":
		return 3
	case h.Protocol == "vless" && h.Transport == "grpc":
		return 4
	case h.Protocol == "shadowsocks":
		return 5
	default:
		return 6
	}
}

// Native subscriptions retain URI output for unknown clients. Known JSON
// consumers can preserve the Auto profile's routing without an app-wide rule.
func NativeAutoFormat(userAgent, path string) string {
	switch path {
	case "json", "v2ray-json":
		return "XRAY_JSON"
	case "singbox":
		return "SINGBOX"
	case "mihomo":
		return "MIHOMO"
	case "stash":
		return "STASH"
	case "clash":
		return "CLASH"
	}
	if jsonClient.MatchString(userAgent) || strings.HasPrefix(strings.ToLower(userAgent), "wps/") {
		return "XRAY_JSON"
	}
	return "XRAY_BASE64"
}

func NativeTemplate(format string) Options {
	switch format {
	case "XRAY_JSON":
		return Options{"log": Options{"loglevel": "warning"}, "inbounds": []any{Options{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": Options{"udp": true}, "sniffing": Options{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}}}, "outbounds": []any{Options{"tag": "direct", "protocol": "freedom"}, Options{"tag": "block", "protocol": "blackhole"}}}
	case "SINGBOX":
		return Options{"inbounds": []any{Options{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}}, "outbounds": []any{Options{"type": "selector", "tag": "PAUK", "outbounds": []any{}}, Options{"type": "direct", "tag": "direct"}}, "route": Options{"final": "PAUK", "auto_detect_interface": true}}
	case "MIHOMO", "STASH", "CLASH":
		return Options{"mixed-port": 7890, "allow-lan": false, "mode": "rule", "proxy-groups": []any{Options{"name": "PAUK", "type": "select", "proxies": []any{}}}, "rules": []any{"MATCH,PAUK"}}
	}
	return Options{}
}
