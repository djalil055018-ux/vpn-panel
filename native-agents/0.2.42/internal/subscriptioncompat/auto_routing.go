package subscriptioncompat

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// A reviewed, pinned snapshot is shipped with the binary. Subscription import
// does not depend on downloading geosite files through an unstarted tunnel.
//
//go:embed rules/russia.json
var russiaRulesJSON []byte

type geographicRules struct {
	Suffix []string `json:"domain_suffix"`
	Domain []string `json:"domain"`
	Regex  []string `json:"domain_regex"`
	CIDR   []string `json:"ip_cidr"`
}

var russiaRules = func() geographicRules {
	var r geographicRules
	if json.Unmarshal(russiaRulesJSON, &r) != nil {
		panic("invalid embedded routing rules")
	}
	return r
}()

func russianXrayDomains() []string {
	rules := make([]string, 0, len(russiaRules.Suffix)+len(russiaRules.Domain)+len(russiaRules.Regex))
	for _, s := range russiaRules.Suffix {
		rules = append(rules, "domain:"+s)
	}
	for _, s := range russiaRules.Domain {
		rules = append(rules, "full:"+s)
	}
	for _, s := range russiaRules.Regex {
		rules = append(rules, "regexp:"+s)
	}
	return rules
}

func applyAutoXray(cfg Options, h Host) {
	if !h.Automatic {
		return
	}
	// Owned routing on the separate Auto profile cannot inherit an imported
	// catch-all DIRECT rule. Manual profiles retain their original template.
	rules := []any{
		Options{"type": "field", "inboundTag": []string{"pauk-dns-query"}, "outboundTag": "proxy"},
		Options{"type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "pauk-dns-out"},
	}
	if h.AutoRussiaDirect {
		retained := []any{}
		for _, out := range cfg["outbounds"].([]any) {
			if text(object(out)["tag"]) != "pauk-ru-direct" {
				retained = append(retained, out)
			}
		}
		cfg["outbounds"] = append(retained, Options{"tag": "pauk-ru-direct", "protocol": "freedom", "settings": Options{"domainStrategy": "UseIPv4"}})
		// Keep the Xray JSON profile small enough for mobile subscription import.
		// The application has the requested hostname while establishing HTTP/TLS,
		// so the Russian website rule applies before any IP route is required.
		// Raw numeric addresses remain on the VPN path by the final proxy rule.
		rules = append(rules, Options{"type": "field", "domain": russianXrayDomains(), "outboundTag": "pauk-ru-direct"})
	}
	rules = append(rules, Options{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
	// Domain routing is enough for websites and avoids delivering a very large
	// country-CIDR list to mobile clients.
	cfg["routing"] = Options{"domainStrategy": "AsIs", "rules": rules}
	if inbounds, ok := cfg["inbounds"].([]any); ok {
		for _, in := range inbounds {
			b := object(in)
			if b != nil {
				b["sniffing"] = Options{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
			}
		}
	}
}

func autoHost(hosts []Host) (Host, bool) {
	for _, h := range hosts {
		if h.Automatic {
			return h, true
		}
	}
	return Host{}, false
}

func applyAutoStructured(raw []byte, hosts []Host, format string) ([]byte, error) {
	h, ok := autoHost(hosts)
	if !ok || (format != "SINGBOX" && format != "MIHOMO" && format != "STASH" && format != "CLASH") {
		return raw, nil
	}
	var cfg Options
	if json.Unmarshal(raw, &cfg) != nil {
		return nil, ErrProfile
	}
	if format == "SINGBOX" {
		outbounds, _ := cfg["outbounds"].([]any)
		autoTag := ""
		for _, out := range outbounds {
			o := object(out)
			switch text(o["type"]) {
			case "vless", "trojan", "hysteria2", "shadowsocks":
				autoTag = text(o["tag"])
			}
			if autoTag != "" {
				break
			}
		}
		if autoTag == "" {
			return nil, ErrProfile
		}
		final := autoTag
		for _, out := range outbounds {
			o := object(out)
			if o["type"] == "selector" {
				values, _ := o["outbounds"].([]any)
				for _, v := range values {
					if v == autoTag {
						o["default"] = autoTag
						if final == autoTag {
							final = text(o["tag"])
						}
						break
					}
				}
			}
		}
		retained := []any{}
		for _, out := range outbounds {
			if text(object(out)["tag"]) != "pauk-ru-direct" {
				retained = append(retained, out)
			}
		}
		cfg["outbounds"] = append(retained, Options{"type": "direct", "tag": "pauk-ru-direct"})
		rules := []any{Options{"action": "sniff"}, Options{"protocol": "dns", "action": "hijack-dns"}}
		if h.AutoRussiaDirect {
			rules = append(rules, Options{"domain_suffix": russiaRules.Suffix, "domain": russiaRules.Domain, "domain_regex": russiaRules.Regex, "action": "route", "outbound": "pauk-ru-direct"}, Options{"action": "resolve", "server": "pauk-remote", "strategy": "ipv4_only"}, Options{"ip_cidr": russiaRules.CIDR, "action": "route", "outbound": "pauk-ru-direct"})
		}
		cfg["route"] = Options{"rules": rules, "final": final, "auto_detect_interface": true, "default_domain_resolver": "pauk-bootstrap"}
		cfg["dns"] = Options{"servers": []any{
			Options{"type": "https", "tag": "pauk-bootstrap", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "pauk-ru-direct"},
			Options{"type": "https", "tag": "pauk-remote", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": final},
		}, "final": "pauk-remote", "strategy": "ipv4_only"}
	} else {
		proxies, _ := cfg["proxies"].([]any)
		if len(proxies) == 0 {
			return nil, ErrProfile
		}
		autoTag := text(object(proxies[0])["name"])
		groups, _ := cfg["proxy-groups"].([]any)
		selector := "PAUK · Выбор"
		used := map[string]bool{}
		for _, p := range proxies {
			used[text(object(p)["name"])] = true
		}
		for _, g := range groups {
			used[text(object(g)["name"])] = true
		}
		for used[selector] {
			selector += " ·"
		}
		names := []any{autoTag}
		for _, p := range proxies[1:] {
			names = append(names, object(p)["name"])
		}
		cfg["proxy-groups"] = append([]any{Options{"name": selector, "type": "select", "proxies": names}}, groups...)
		rules := []string{}
		if h.AutoRussiaDirect {
			for _, s := range russiaRules.Suffix {
				rules = append(rules, "DOMAIN-SUFFIX,"+s+",DIRECT")
			}
			for _, s := range russiaRules.Domain {
				rules = append(rules, "DOMAIN,"+s+",DIRECT")
			}
			// The pinned geographic source is required not to contain regex entries:
			// Clash-family regex syntax varies, so never silently translate them.
			if len(russiaRules.Regex) > 0 {
				return nil, ErrProfile
			}
			for _, s := range russiaRules.CIDR {
				kind := "IP-CIDR"
				if strings.Contains(s, ":") {
					kind = "IP-CIDR6"
				}
				rules = append(rules, kind+","+s+",DIRECT")
			}
		}
		rules = append(rules, "MATCH,"+selector)
		cfg["rules"] = rules
		cfg["mode"] = "rule"
		cfg["dns"] = Options{"enable": true, "ipv6": false, "enhanced-mode": "redir-host", "respect-rules": true, "default-nameserver": []string{"1.1.1.1", "8.8.8.8"}, "proxy-server-nameserver": []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}, "nameserver": []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}}
	}
	return json.Marshal(cfg)
}

func SetAutoNetworkHeaders(headers http.Header, userAgent, format string, profile AutoProfile) {
	headers.Set("X-PAUK-Auto-Name", "base64:"+base64.StdEncoding.EncodeToString([]byte(profile.Name)))
	headers.Set("X-PAUK-Auto-Assignment", "subscription-refresh")
	mode := "disabled"
	if profile.RussiaDirect {
		switch format {
		case "XRAY_JSON":
			mode = "profile"
		case "SINGBOX", "MIHOMO", "STASH", "CLASH":
			mode = "configuration"
		default:
			mode = "client-rules-required"
		}
	}
	headers.Set("X-PAUK-Russia-Direct", mode)
	// Full configs already carry DNS and routing. Do not attach the older
	// Happ global-proxy routing preset, which contradicts Russia-direct.
	if format != "XRAY_BASE64" && strings.HasPrefix(strings.ToLower(userAgent), "happ/") {
		headers.Del("Routing")
	}
}
