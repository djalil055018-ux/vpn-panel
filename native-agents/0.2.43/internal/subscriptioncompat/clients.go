package subscriptioncompat

import (
	"encoding/json"
	"strings"
)

func alpn(v any) []string {
	out := []string{}
	for _, s := range strings.Split(text(v), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
func fingerprint(h Host) string {
	f := strings.ToLower(text(h.SecurityOptions["fingerprint"]))
	for _, name := range []string{"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"} {
		if strings.Contains(f, name) {
			return name
		}
	}
	return "chrome"
}
func singboxOutbound(h Host, credential string) Options {
	if h.Protocol == "shadowsocks" {
		return Options{"tag": h.Name, "type": "shadowsocks", "server": h.Address, "server_port": h.Port, "method": "2022-blake3-aes-256-gcm", "password": h.NativeShadowsocksPassword}
	}
	kind := h.Protocol
	if kind == "hysteria" {
		kind = "hysteria2"
	}
	out := Options{"tag": h.Name, "type": kind, "server": h.Address, "server_port": h.Port}
	tls := Options{"enabled": true}
	putText(tls, "server_name", h.SecurityOptions["serverName"])
	if kind == "hysteria2" {
		out["password"] = credential
		if values := alpn(h.SecurityOptions["alpn"]); len(values) > 0 {
			tls["alpn"] = values
		}
	} else {
		if kind == "trojan" {
			out["password"] = credential
		} else {
			out["uuid"] = credential
		}
		putText(out, "flow", h.ProtocolOptions["flow"])
		if h.Security == "none" {
			return out
		}
		if h.Transport == "ws" {
			out["transport"] = Options{"type": "ws", "path": text(h.TransportOptions["path"]), "headers": Options{"Host": text(h.TransportOptions["host"])}}
		}
		if h.Transport == "grpc" {
			out["transport"] = Options{"type": "grpc", "service_name": text(h.TransportOptions["serviceName"])}
		}
		tls["utls"] = Options{"enabled": true, "fingerprint": fingerprint(h)}
		if h.Security == "reality" {
			r := Options{"enabled": true, "public_key": text(h.SecurityOptions["publicKey"])}
			putText(r, "short_id", h.SecurityOptions["shortId"])
			tls["reality"] = r
		} else if values := alpn(h.SecurityOptions["alpn"]); len(values) > 0 {
			tls["alpn"] = values
		}
	}
	out["tls"] = tls
	return out
}

func arrayField(v Options, key string) ([]any, error) {
	if value, exists := v[key]; exists {
		if value == nil {
			return []any{}, nil
		}
		out, ok := value.([]any)
		if !ok {
			return nil, ErrProfile
		}
		return out, nil
	}
	return []any{}, nil
}
func renderSingbox(hosts []Host, template Options, credential string) ([]byte, error) {
	cfg := copyObject(template)
	outbounds, err := arrayField(cfg, "outbounds")
	if err != nil {
		return nil, err
	}
	reserved := []string{}
	if _, automatic := autoHost(hosts); automatic {
		reserved = append(reserved, "pauk-ru-direct")
	}
	for _, o := range outbounds {
		reserved = append(reserved, text(object(o)["tag"]))
		switch text(object(o)["type"]) {
		case "direct", "block", "dns", "selector", "urltest":
		default:
			return nil, ErrProfile
		}
	}
	endpoints, err := arrayField(cfg, "endpoints")
	if err != nil {
		return nil, err
	}
	for _, endpoint := range endpoints {
		reserved = append(reserved, text(object(endpoint)["tag"]))
	}
	selected := []Host{}
	for _, h := range hosts {
		if skipped(h, "SINGBOX") || h.Transport == "xhttp" {
			continue
		}
		selected = append(selected, h)
	}
	for _, h := range uniqueClientHostNames(selected, reserved) {
		outbounds = append(outbounds, singboxOutbound(h, credential))
	}
	tests, selectors := []any{}, []any{}
	for _, o := range outbounds {
		entry := object(o)
		kind := text(entry["type"])
		if kind == "vless" || kind == "hysteria2" || kind == "trojan" || kind == "shadowsocks" {
			tests = append(tests, entry["tag"])
			selectors = append(selectors, entry["tag"])
		}
		if kind == "urltest" {
			selectors = append(selectors, entry["tag"])
		}
	}
	for _, o := range outbounds {
		entry := object(o)
		control := object(entry["remnawave"])
		delete(entry, "remnawave")
		if control["includeProxies"] == false {
			continue
		}
		switch entry["type"] {
		case "selector":
			entry["outbounds"] = selectors
		case "urltest":
			entry["outbounds"] = tests
		}
	}
	cfg["outbounds"] = outbounds
	return json.Marshal(cfg)
}

func mihomoProxy(h Host, credential string) Options {
	if h.Protocol == "shadowsocks" {
		return Options{"name": h.Name, "type": "ss", "server": h.Address, "port": h.Port, "udp": true, "cipher": "2022-blake3-aes-256-gcm", "password": h.NativeShadowsocksPassword}
	}
	node := Options{"name": h.Name, "server": h.Address, "port": h.Port, "udp": true, "client-fingerprint": fingerprint(h)}
	if h.Protocol == "hysteria" {
		node["type"] = "hysteria2"
		node["password"] = credential
		putText(node, "sni", h.SecurityOptions["serverName"])
		if values := alpn(h.SecurityOptions["alpn"]); len(values) > 0 {
			node["alpn"] = values
		}
		return node
	}
	node["type"] = h.Protocol
	node["network"] = h.Transport
	if h.Protocol == "trojan" {
		node["password"] = credential
		putText(node, "sni", h.SecurityOptions["serverName"])
	} else {
		node["uuid"] = credential
		node["packet-encoding"] = "xudp"
	}
	if h.Security != "none" {
		node["tls"] = true
		node["servername"] = text(h.SecurityOptions["serverName"])
	}
	putText(node, "flow", h.ProtocolOptions["flow"])
	if h.Security == "reality" {
		node["reality-opts"] = Options{"public-key": text(h.SecurityOptions["publicKey"]), "short-id": valueOr(h.SecurityOptions["shortId"], "")}
	} else if values := alpn(h.SecurityOptions["alpn"]); len(values) > 0 {
		node["alpn"] = values
	}
	switch h.Transport {
	case "ws":
		node["ws-opts"] = Options{"path": text(h.TransportOptions["path"]), "headers": Options{"Host": text(h.TransportOptions["host"])}}
	case "grpc":
		node["grpc-opts"] = Options{"grpc-service-name": text(h.TransportOptions["serviceName"])}
	case "xhttp":
		opts := Options{}
		for _, k := range []string{"path", "host", "mode"} {
			putText(opts, k, h.TransportOptions[k])
		}
		if len(object(h.TransportOptions["extra"])) > 0 {
			opts["extra"] = clone(h.TransportOptions["extra"])
		}
		if len(opts) > 0 {
			node["xhttp-opts"] = opts
		}
	}
	return node
}

// JSON is valid YAML and preserves the parsed template's value types exactly.
// The HTTP layer uses the requested client MIME type; no template comments or
// YAML formatting are part of the subscription semantics.
func renderYAMLFamily(hosts []Host, template Options, format, credential string) ([]byte, error) {
	cfg := copyObject(template)
	if cfg["proxy-providers"] != nil {
		return nil, ErrProfile
	}
	if control := object(cfg["remnawave"]); len(control) > 0 {
		if format == "CLASH" || len(control) != 1 || control["includeHiddenHosts"] != false {
			return nil, ErrProfile
		}
		delete(cfg, "remnawave")
	}
	original, err := arrayField(cfg, "proxies")
	if err != nil || len(original) > 0 {
		return nil, ErrProfile
	}
	groups, err := arrayField(cfg, "proxy-groups")
	if err != nil {
		return nil, err
	}
	reserved := []string{"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE", "GLOBAL"}
	for _, g := range groups {
		reserved = append(reserved, text(object(g)["name"]))
	}
	selected := []Host{}
	for _, h := range hosts {
		if skipped(h, format) || (format == "CLASH" && h.Protocol != "trojan") || (format == "STASH" && h.Transport == "xhttp") {
			continue
		}
		selected = append(selected, h)
	}
	proxies, names := []any{}, []any{}
	for _, h := range uniqueClientHostNames(selected, reserved) {
		proxies = append(proxies, mihomoProxy(h, credential))
		names = append(names, h.Name)
	}
	for _, g := range groups {
		group := object(g)
		if group == nil {
			return nil, ErrProfile
		}
		current, err := arrayField(group, "proxies")
		if err != nil {
			return nil, err
		}
		control := object(group["remnawave"])
		for k, v := range control {
			if k != "include-proxies" || (v != true && v != false) {
				return nil, ErrProfile
			}
		}
		delete(group, "remnawave")
		if control["include-proxies"] != false {
			current = append(current, names...)
		}
		group["proxies"] = current
	}
	cfg["proxies"] = proxies
	cfg["proxy-groups"] = groups
	return json.Marshal(cfg)
}
