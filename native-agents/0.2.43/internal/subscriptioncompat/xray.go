package subscriptioncompat

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func xrayStream(h Host, credential string) Options {
	stream := Options{"network": h.Transport, "security": h.Security}
	t, s := h.TransportOptions, h.SecurityOptions
	switch h.Transport {
	case "tcp":
		tcp := Options{}
		if t["header"] != nil {
			tcp["header"] = clone(t["header"])
		}
		stream["tcpSettings"] = tcp
	case "ws":
		stream["wsSettings"] = Options{"path": text(t["path"]), "host": text(t["host"])}
	case "grpc":
		// Xray's field is multiMode. Remna3.4.3 emitted an ignored "mode" boolean.
		stream["grpcSettings"] = Options{"serviceName": valueOr(t["serviceName"], ""), "authority": valueOr(t["authority"], ""), "multiMode": truth(t["multiMode"])}
	case "xhttp":
		xhttp := Options{"mode": valueOr(t["mode"], "auto"), "host": valueOr(t["host"], ""), "path": valueOr(t["path"], "")}
		if len(object(t["extra"])) > 0 {
			xhttp["extra"] = clone(t["extra"])
		}
		stream["xhttpSettings"] = xhttp
	case "hysteria":
		stream["hysteriaSettings"] = Options{"version": 2, "auth": credential}
	}
	if h.Security == "reality" {
		r := Options{"serverName": text(s["serverName"]), "publicKey": text(s["publicKey"]), "fingerprint": text(s["fingerprint"])}
		for _, name := range []string{"shortId", "spiderX", "mldsa65Verify"} {
			putText(r, name, s[name])
		}
		stream["realitySettings"] = r
	} else if h.Security == "tls" {
		tls := Options{"serverName": text(s["serverName"]), "enableSessionResumption": truth(s["enableSessionResumption"]), "fingerprint": text(s["fingerprint"])}
		if alpn := text(s["alpn"]); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		for _, name := range []string{"echConfigList", "echForceQuery", "cipherSuites"} {
			putText(tls, name, s[name])
		}
		if len(object(s["echSockopt"])) > 0 {
			tls["echSockopt"] = clone(s["echSockopt"])
		}
		for _, name := range []string{"pinnedPeerCertSha256", "verifyPeerCertByName"} {
			if v := text(s[name]); v != "" {
				tls[name] = strings.Split(v, ",")
			}
		}
		stream["tlsSettings"] = tls
	}
	if len(h.Stream.Sockopt) > 0 {
		stream["sockopt"] = clone(h.Stream.Sockopt)
	}
	if len(h.Stream.FinalMask) > 0 {
		stream["finalmask"] = clone(h.Stream.FinalMask)
	}
	return stream
}

func xrayOutbound(h Host, credential string) Options {
	if h.Protocol == "shadowsocks" {
		return Options{"tag": "proxy", "protocol": "shadowsocks", "settings": Options{"servers": []any{Options{"address": h.Address, "port": h.Port, "method": "2022-blake3-aes-256-gcm", "password": h.NativeShadowsocksPassword}}}, "streamSettings": Options{"network": "tcp", "security": "none"}}
	}
	var settings Options
	if h.Protocol == "vless" {
		settings = Options{"vnext": []any{Options{"address": h.Address, "port": h.Port, "users": []any{Options{"id": credential, "encryption": "none", "flow": text(h.ProtocolOptions["flow"])}}}}}
	} else if h.Protocol == "trojan" {
		settings = Options{"servers": []any{Options{"address": h.Address, "port": h.Port, "password": credential}}}
	} else {
		settings = Options{"address": h.Address, "port": h.Port, "version": 2}
	}
	out := Options{"tag": "proxy", "protocol": h.Protocol, "settings": settings, "streamSettings": xrayStream(h, credential)}
	if len(h.Mux) > 0 {
		mux := copyObject(h.Mux)
		delete(mux, "smux")
		if len(mux) > 0 {
			out["mux"] = mux
		}
	}
	return out
}

func renderXrayJSON(hosts []Host, template Options, credential string) ([]byte, error) {
	if template["remnawave"] != nil {
		return nil, ErrProfile
	}
	existing := []any{}
	if v, ok := template["outbounds"]; ok {
		var valid bool
		existing, valid = v.([]any)
		if !valid {
			return nil, ErrProfile
		}
	}
	configs := []any{}
	for _, h := range hosts {
		if skipped(h, "XRAY_JSON") {
			continue
		}
		cfg := copyObject(template)
		cfg["remarks"] = h.Name
		cfg["outbounds"] = append([]any{xrayOutbound(h, credential)}, existing...)
		configs = append(configs, cfg)
	}
	return json.Marshal(configs)
}

func shareURI(h Host, credential string) (string, error) {
	if h.Protocol == "shadowsocks" {
		u := url.URL{Scheme: "ss", User: url.UserPassword("2022-blake3-aes-256-gcm", h.NativeShadowsocksPassword), Host: net.JoinHostPort(h.Address, strconv.Itoa(h.Port)), Fragment: h.Name}
		return u.String(), nil
	}
	scheme := h.Protocol
	q := url.Values{}
	t, s := h.TransportOptions, h.SecurityOptions
	if h.Protocol == "hysteria" {
		scheme = "hysteria2"
		if v := text(s["serverName"]); v != "" {
			q.Set("sni", v)
		}
		if len(h.Stream.FinalMask) > 0 {
			raw, err := json.Marshal(h.Stream.FinalMask)
			if err != nil {
				return "", ErrProfile
			}
			q.Set("fm", string(raw))
		}
	} else {
		if h.Protocol == "vless" {
			q.Set("encryption", "none")
		}
		if flow := text(h.ProtocolOptions["flow"]); flow != "" {
			q.Set("flow", flow)
		}
		q.Set("type", h.Transport)
		q.Set("security", h.Security)
		for field, param := range map[string]string{"serverName": "sni", "fingerprint": "fp", "publicKey": "pbk", "shortId": "sid", "spiderX": "spx", "mldsa65Verify": "pqv", "alpn": "alpn", "echConfigList": "ech"} {
			if v := text(s[field]); v != "" {
				q.Set(param, v)
			}
		}
		switch h.Transport {
		case "ws":
			q.Set("path", text(t["path"]))
			q.Set("host", text(t["host"]))
		case "grpc":
			if v := text(t["serviceName"]); v != "" {
				q.Set("serviceName", v)
			}
			if v := text(t["authority"]); v != "" {
				q.Set("authority", v)
			}
			mode := "gun"
			if truth(t["multiMode"]) {
				mode = "multi"
			}
			q.Set("mode", mode)
		case "xhttp":
			for _, field := range []string{"path", "host", "mode"} {
				if v := text(t[field]); v != "" {
					q.Set(field, v)
				}
			}
			if len(object(t["extra"])) > 0 {
				raw, _ := json.Marshal(t["extra"])
				q.Set("extra", string(raw))
			}
		case "tcp":
			if len(object(t["header"])) > 0 {
				return "", ErrProfile
			}
		}
	}
	uri := url.URL{Scheme: scheme, User: url.User(credential), Host: net.JoinHostPort(h.Address, strconv.Itoa(h.Port)), RawQuery: q.Encode(), Fragment: h.Name}
	return uri.String(), nil
}

func renderBase64(hosts []Host, credential string) ([]byte, error) {
	links := []string{}
	for _, h := range hosts {
		if skipped(h, "XRAY_BASE64") {
			continue
		}
		link, err := shareURI(h, credential)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))), nil
}

// Render accepts an already authorized host set. Never pass a whole source
// account inventory here or serialize the returned client configuration in logs.
// Additional public formats are implemented by separate adapters.
func Render(hosts []Host, template Options, format, credential string) ([]byte, error) {
	if !credentialPattern.MatchString(credential) || len(hosts) > 1000 {
		return nil, ErrProfile
	}
	for _, h := range hosts {
		if !validHost(h) {
			return nil, ErrProfile
		}
		if format != "XRAY_BASE64" && format != "XRAY_JSON" && h.Transport == "grpc" && (truth(h.TransportOptions["multiMode"]) || text(h.TransportOptions["authority"]) != "") {
			return nil, ErrProfile
		}
	}
	return renderValidated(hosts, template, format, credential)
}

func renderValidated(hosts []Host, template Options, format, credential string) ([]byte, error) {
	switch format {
	case "XRAY_BASE64":
		return renderBase64(hosts, credential)
	case "XRAY_JSON":
		return renderXrayJSON(hosts, template, credential)
	case "SINGBOX":
		return renderSingbox(hosts, template, credential)
	case "MIHOMO", "STASH", "CLASH":
		return renderYAMLFamily(hosts, template, format, credential)
	default:
		return nil, ErrProfile
	}
}

// ShareURI renders one authorized, validated profile with the current client credential.
func ShareURI(h Host, credential string) (string, error) {
	if !credentialPattern.MatchString(credential) || !validHost(h) {
		return "", ErrProfile
	}
	return shareURI(h, credential)
}
