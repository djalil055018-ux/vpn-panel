package xrayprofile

import (
	"crypto/ecdh"
	"encoding/base64"
	"net"
	"path"
	"strings"
)

func validateConfig(cfg map[string]any, source bool) error {
	if _, ok := obj(cfg, "log", "dns", "inbounds", "outbounds", "routing"); !ok {
		return ErrProfile
	}
	if log, exists := cfg["log"]; exists {
		m, ok := obj(log, "loglevel")
		if !ok || !oneOf(m["loglevel"], "none", "error", "warning", "info", "debug") {
			return ErrProfile
		}
	}
	if dns, exists := cfg["dns"]; exists {
		m, ok := obj(dns, "servers")
		if !ok || !stringsArray(m["servers"], 1, 32, false) {
			return ErrProfile
		}
	}
	inbounds, ok := cfg["inbounds"].([]any)
	if !ok || len(inbounds) == 0 || len(inbounds) > 128 {
		return ErrProfile
	}
	inTags := map[string]bool{}
	listeners := map[string]bool{}
	for _, value := range inbounds {
		in, ok := obj(value, "tag", "listen", "port", "protocol", "settings", "streamSettings", "sniffing")
		if !ok || !text(in["tag"]) || len(str(in["tag"])) > 128 || str(in["tag"]) == blockTag || str(in["tag"]) == "api" || inTags[str(in["tag"])] {
			return ErrProfile
		}
		inTags[str(in["tag"])] = true
		if !text(in["listen"]) || net.ParseIP(str(in["listen"])) == nil || !integer(in["port"], 1, 65535) || strNumber(in["port"]) == "10085" {
			return ErrProfile
		}
		if !oneOf(in["protocol"], "vless", "hysteria") {
			return ErrProfile
		}
		stream, ok := obj(in["streamSettings"], "network", "security", "realitySettings", "tlsSettings", "grpcSettings", "xhttpSettings", "hysteriaSettings", "finalmask")
		if !ok || validateStream(stream, source, str(in["protocol"])) != nil {
			return ErrProfile
		}
		kind := "tcp"
		if str(in["protocol"]) == "hysteria" {
			kind = "udp"
		}
		listener := kind + "/" + str(in["listen"]) + "/" + strNumber(in["port"])
		if listeners[listener] {
			return ErrProfile
		}
		listeners[listener] = true
		settings, ok := obj(in["settings"], "clients", "decryption", "version", "flow")
		if !ok {
			return ErrProfile
		}
		clients, ok := settings["clients"].([]any)
		if !ok || len(clients) != 0 {
			return ErrProfile
		}
		if str(in["protocol"]) == "vless" {
			if str(settings["decryption"]) != "none" || settings["version"] != nil || !optional(settings, "flow", func(v any) bool { return oneOf(v, "", "none", "xtls-rprx-vision") }) {
				return ErrProfile
			}
			if str(settings["flow"]) == "xtls-rprx-vision" && !oneOf(stream["network"], "raw", "tcp") {
				return ErrProfile
			}
		} else if !integer(settings["version"], 2, 2) || settings["decryption"] != nil || settings["flow"] != nil {
			return ErrProfile
		}
		if v, exists := in["sniffing"]; exists {
			sniff, ok := obj(v, "enabled", "destOverride", "routeOnly", "metadataOnly")
			if !ok || !boolean(sniff["enabled"]) || !stringsArray(sniff["destOverride"], 0, 8, false) || !optional(sniff, "routeOnly", boolean) || !optional(sniff, "metadataOnly", boolean) {
				return ErrProfile
			}
			for _, entry := range sniff["destOverride"].([]any) {
				if !oneOf(entry, "http", "tls", "quic", "fakedns", "fakedns+others") {
					return ErrProfile
				}
			}
		}
	}
	outbounds, ok := cfg["outbounds"].([]any)
	if !ok || len(outbounds) == 0 || len(outbounds) > 128 {
		return ErrProfile
	}
	outTags := map[string]bool{}
	for _, value := range outbounds {
		out, ok := obj(value, "tag", "protocol", "settings", "streamSettings")
		if !ok || !text(out["tag"]) || len(str(out["tag"])) > 128 || str(out["tag"]) == blockTag || str(out["tag"]) == "api" || outTags[str(out["tag"])] || !oneOf(out["protocol"], "freedom", "blackhole") {
			return ErrProfile
		}
		outTags[str(out["tag"])] = true
		if v, exists := out["settings"]; exists {
			settings, ok := obj(v, "domainStrategy")
			if !ok || (str(out["protocol"]) == "blackhole" && len(settings) != 0) || !optional(settings, "domainStrategy", func(v any) bool {
				return oneOf(v, "AsIs", "UseIP", "UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4", "ForceIP", "ForceIPv4", "ForceIPv6", "ForceIPv4v6", "ForceIPv6v4")
			}) {
				return ErrProfile
			}
		}
		if v, exists := out["streamSettings"]; exists {
			stream, ok := obj(v, "sockopt")
			if !ok || str(out["protocol"]) != "freedom" {
				return ErrProfile
			}
			sock, ok := obj(stream["sockopt"], "interface", "tcpFastOpen")
			if !ok || !text(sock["interface"]) || len(str(sock["interface"])) > 64 || strings.ContainsAny(str(sock["interface"]), "/\\ \t") || !optional(sock, "tcpFastOpen", boolean) {
				return ErrProfile
			}
		}
	}
	if value, exists := cfg["routing"]; exists {
		routing, ok := obj(value, "rules", "domainStrategy")
		if !ok || !optional(routing, "domainStrategy", func(v any) bool { return oneOf(v, "AsIs", "IPIfNonMatch", "IPOnDemand") }) {
			return ErrProfile
		}
		rules, ok := routing["rules"].([]any)
		if !ok || len(rules) > 512 {
			return ErrProfile
		}
		for _, value := range rules {
			rule, ok := obj(value, "type", "ip", "domain", "protocol", "network", "port", "inboundTag", "outboundTag")
			if !ok || !outTags[str(rule["outboundTag"])] || !optional(rule, "type", func(v any) bool { return v == "field" }) || !optional(rule, "network", func(v any) bool { return oneOf(v, "tcp", "udp", "tcp,udp") }) || !optional(rule, "port", text) {
				return ErrProfile
			}
			matched := false
			for _, key := range []string{"ip", "domain", "protocol", "inboundTag"} {
				if v, exists := rule[key]; exists {
					if !stringsArray(v, 1, 1000, false) {
						return ErrProfile
					}
					matched = true
					if key == "inboundTag" {
						for _, tag := range v.([]any) {
							if !inTags[str(tag)] {
								return ErrProfile
							}
						}
					}
				}
			}
			if !matched && rule["network"] == nil && rule["port"] == nil {
				return ErrProfile
			}
		}
	}
	return nil
}

func validateStream(m map[string]any, source bool, protocol string) error {
	if !oneOf(m["security"], "reality", "tls") {
		return ErrProfile
	}
	if protocol == "hysteria" {
		if str(m["network"]) != "hysteria" || str(m["security"]) != "tls" || m["grpcSettings"] != nil || m["xhttpSettings"] != nil {
			return ErrProfile
		}
		h, ok := obj(m["hysteriaSettings"], "version")
		if !ok || !integer(h["version"], 2, 2) {
			return ErrProfile
		}
	} else {
		if !oneOf(m["network"], "raw", "tcp", "grpc", "xhttp") || m["hysteriaSettings"] != nil || m["finalmask"] != nil {
			return ErrProfile
		}
	}
	if str(m["network"]) == "grpc" {
		g, ok := obj(m["grpcSettings"], "serviceName", "multiMode")
		if !ok || !text(g["serviceName"]) || !optional(g, "multiMode", boolean) {
			return ErrProfile
		}
	} else if m["grpcSettings"] != nil {
		return ErrProfile
	}
	if str(m["network"]) == "xhttp" {
		x, ok := obj(m["xhttpSettings"], "path", "mode", "noGRPCHeader", "scMaxBufferedPosts", "scMaxEachPostBytes", "xPaddingBytes")
		if !ok || !text(x["path"]) || !strings.HasPrefix(str(x["path"]), "/") || !oneOf(x["mode"], "auto", "packet-up", "stream-up", "stream-one") || !optional(x, "noGRPCHeader", boolean) {
			return ErrProfile
		}
		if !optional(x, "scMaxBufferedPosts", func(v any) bool { return integer(v, 0, 1000000) }) {
			return ErrProfile
		}
		for _, key := range []string{"scMaxEachPostBytes", "xPaddingBytes"} {
			if !optional(x, key, func(v any) bool { return text(v) || integer(v, 0, 1<<40) }) {
				return ErrProfile
			}
		}
	} else if m["xhttpSettings"] != nil {
		return ErrProfile
	}
	if str(m["security"]) == "reality" {
		if m["tlsSettings"] != nil {
			return ErrProfile
		}
		r, ok := obj(m["realitySettings"], "dest", "target", "serverNames", "shortIds", "spiderX", "xver", "show", "privateKey")
		if !ok || !stringsArray(r["serverNames"], 1, 64, false) || !stringsArray(r["shortIds"], 1, 64, true) || !optional(r, "spiderX", maybeText) || !optional(r, "show", boolean) || !optional(r, "xver", func(v any) bool { return integer(v, 0, 2) }) {
			return ErrProfile
		}
		if (r["dest"] == nil) == (r["target"] == nil) {
			return ErrProfile
		}
		target := str(r["dest"])
		if target == "" {
			target = str(r["target"])
		}
		if !validRealityTarget(target) {
			return ErrProfile
		}
		for _, value := range r["shortIds"].([]any) {
			if !shortID.MatchString(str(value)) {
				return ErrProfile
			}
		}
		if source {
			key, err := base64.RawURLEncoding.DecodeString(str(r["privateKey"]))
			if err != nil {
				return ErrProfile
			}
			if _, err := ecdh.X25519().NewPrivateKey(key); err != nil {
				return ErrProfile
			}
		} else if _, exists := r["privateKey"]; exists {
			return ErrProfile
		}
	} else {
		if m["realitySettings"] != nil {
			return ErrProfile
		}
		t, ok := obj(m["tlsSettings"], "certificates", "alpn", "serverName", "minVersion", "maxVersion")
		if !ok || !optional(t, "alpn", func(v any) bool { return stringsArray(v, 1, 16, false) }) || !optional(t, "serverName", text) || !optional(t, "minVersion", text) || !optional(t, "maxVersion", text) {
			return ErrProfile
		}
		certs, ok := t["certificates"].([]any)
		if !ok || (source && len(certs) != 1) || (!source && len(certs) != 0) {
			return ErrProfile
		}
		for _, value := range certs {
			cert, ok := obj(value, "certificateFile", "keyFile")
			if !ok || !text(cert["certificateFile"]) || !text(cert["keyFile"]) {
				return ErrProfile
			}
			for _, key := range []string{"certificateFile", "keyFile"} {
				file := str(cert[key])
				if !path.IsAbs(file) || path.Clean(file) != file || strings.Contains(file, "\\") {
					return ErrProfile
				}
			}
		}
	}
	if v, exists := m["finalmask"]; exists {
		final, ok := obj(v, "quicParams")
		if !ok {
			return ErrProfile
		}
		q, ok := obj(final["quicParams"], "congestion", "debug")
		if !ok || !oneOf(q["congestion"], "bbr", "reno") || !optional(q, "debug", boolean) {
			return ErrProfile
		}
	}
	return nil
}

// Source RAW profiles use a local TLS frontend with PROXY protocol. Its UNIX
// socket is part of the reviewed node dependency graph, not a remote host:port.
// Abstract sockets and implicit localhost ports are not part of this contract.
func validRealityTarget(target string) bool {
	if !text(target) {
		return false
	}
	if strings.HasPrefix(target, "/") {
		return len(target) <= 107 && path.Clean(target) == target && target != "/" && !strings.Contains(target, "\\")
	}
	host, port, err := net.SplitHostPort(target)
	return err == nil && host != "" && port != ""
}
