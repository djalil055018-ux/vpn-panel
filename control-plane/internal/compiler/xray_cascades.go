package compiler

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

var ErrXrayCascade = errors.New("invalid or incompatible Xray cascade")
var cascadeUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var cascadeDNSLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func XrayCascadeInboundTag(id string) string  { return "pauk-cascade-in-" + id }
func XrayCascadeOutboundTag(id string) string { return "pauk-cascade-out-" + id }

func cascadeHost(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	for _, part := range strings.Split(value, ".") {
		if !cascadeDNSLabel.MatchString(part) {
			return false
		}
	}
	return true
}

func ValidXrayCascadeEndpoint(e model.XrayCascadeEndpoint) bool {
	key, err := base64.RawURLEncoding.DecodeString(e.PublicKey)
	short, shortErr := hex.DecodeString(e.ShortID)
	if !model.ValidCascadeDial(e.ConnectRaceIP, e.ConnectRaceAttempts) || !cascadeHost(e.Address) || !cascadeHost(e.ServerName) || e.Port < 1 || e.Port > 65535 || e.Port == 10085 ||
		!cascadeUUID.MatchString(e.ClientID) || err != nil || len(key) != 32 || shortErr != nil || len(short) > 8 ||
		(e.Flow != "" && e.Flow != "xtls-rprx-vision") {
		return false
	}
	switch e.Fingerprint {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return true
	}
	return false
}

func cascadeService(state model.DesiredState, id string) (string, string, error) {
	found := false
	for _, s := range state.Services {
		if s.ID != id {
			continue
		}
		if found || !cascadeUUID.MatchString(s.ID) || s.Protocol != "vless" || s.Transport != "tcp" || s.Security != "reality" || s.Reality == nil {
			return "", "", ErrXrayCascade
		}
		found = true
	}
	if !found {
		return "", "", ErrXrayCascade
	}
	if state.XrayProfile == nil {
		return id, "", nil
	}
	flow, err := xrayprofile.VLESSFlow(state.XrayProfile, id)
	if err != nil {
		return "", "", ErrXrayCascade
	}
	for _, b := range state.XrayProfile.Bindings {
		if b.ServiceID == id {
			return b.InboundTag, flow, nil
		}
	}
	return "", "", ErrXrayCascade
}

func cascadeClients(clients []model.ClientSpec, flow string) ([]any, error) {
	result := make([]any, 0, len(clients))
	ids, stats := map[string]bool{}, map[string]bool{}
	for _, c := range clients {
		if !cascadeUUID.MatchString(c.ID) || !cascadeUUID.MatchString(c.StatsKey) || ids[c.ID] || stats[c.StatsKey] || c.PPTP != nil || c.WireGuard != nil {
			return nil, ErrXrayCascade
		}
		ids[c.ID], stats[c.StatsKey] = true, true
		value := map[string]any{"id": c.ID, "email": "client-" + c.StatsKey + "@vpn-platform.invalid", "level": 0}
		if flow != "" {
			value["flow"] = flow
		}
		result = append(result, value)
	}
	return result, nil
}

// compileXrayCascades extends a successfully validated native/imported graph.
// The original graph and ordinary authorizations are never supplied by callers
// of the cascade API. There is exactly one outbound for each cascade listener;
// an unavailable exit therefore has no direct fallback.
func compileXrayCascades(raw []byte, state model.DesiredState) ([]byte, error) {
	plan := state.XrayCascades
	if plan == nil {
		return raw, nil
	}
	if plan.Version != 1 || state.Core.Type != "xray" || len(plan.Entries)+len(plan.Exits) == 0 || len(plan.Entries)+len(plan.Exits) > 128 {
		return nil, ErrXrayCascade
	}
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil {
		return nil, ErrXrayCascade
	}
	inbounds, inOK := cfg["inbounds"].([]any)
	outbounds, outOK := cfg["outbounds"].([]any)
	routing, routingOK := cfg["routing"].(map[string]any)
	if !inOK || !outOK || !routingOK {
		return nil, ErrXrayCascade
	}
	rules, rulesOK := routing["rules"].([]any)
	if !rulesOK || len(rules) == 0 {
		return nil, ErrXrayCascade
	}
	byTag := map[string]map[string]any{}
	tags, ports, ids, transit := map[string]bool{}, map[int]bool{}, map[string]bool{}, map[string]bool{}
	ordinaryCredentials := map[string]bool{}
	for _, service := range state.Services {
		for _, client := range service.Clients {
			ordinaryCredentials[client.ID] = true
		}
	}
	for _, entry := range plan.Entries {
		for _, client := range entry.Clients {
			ordinaryCredentials[client.ID] = true
		}
	}
	for _, value := range inbounds {
		in, ok := value.(map[string]any)
		if !ok {
			return nil, ErrXrayCascade
		}
		tag, ok := in["tag"].(string)
		if !ok || tags[tag] {
			return nil, ErrXrayCascade
		}
		byTag[tag] = in
		tags[tag] = true
		port, ok := in["port"].(float64)
		if !ok || port != float64(int(port)) {
			return nil, ErrXrayCascade
		}
		ports[int(port)] = true
	}
	for _, value := range outbounds {
		out, ok := value.(map[string]any)
		if !ok {
			return nil, ErrXrayCascade
		}
		if tag, ok := out["tag"].(string); ok {
			tags[tag] = true
		}
	}
	for _, exit := range plan.Exits {
		if !cascadeUUID.MatchString(exit.ID) || ids[exit.ID] || !cascadeUUID.MatchString(exit.ClientID) || transit[exit.ClientID] || ordinaryCredentials[exit.ClientID] {
			return nil, ErrXrayCascade
		}
		ids[exit.ID], transit[exit.ClientID] = true, true
		tag, flow, err := cascadeService(state, exit.ServiceID)
		if err != nil {
			return nil, err
		}
		in := byTag[tag]
		if in == nil {
			return nil, ErrXrayCascade
		}
		settings, ok := in["settings"].(map[string]any)
		if !ok {
			return nil, ErrXrayCascade
		}
		clients, ok := settings["clients"].([]any)
		if !ok {
			return nil, ErrXrayCascade
		}
		for _, value := range clients {
			c, ok := value.(map[string]any)
			if !ok || c["id"] == exit.ClientID {
				return nil, ErrXrayCascade
			}
		}
		// The entry measures user traffic; the transit user has no stats email.
		client := map[string]any{"id": exit.ClientID}
		if flow != "" {
			client["flow"] = flow
		}
		settings["clients"] = append(clients, client)
	}
	cascadeRules := make([]any, 0, len(plan.Entries))
	for _, entry := range plan.Entries {
		inTag, outTag := XrayCascadeInboundTag(entry.ID), XrayCascadeOutboundTag(entry.ID)
		if !cascadeUUID.MatchString(entry.ID) || ids[entry.ID] || tags[inTag] || tags[outTag] || entry.Port < 1 || entry.Port > 65535 || entry.Port == 10085 || ports[entry.Port] || !ValidXrayCascadeEndpoint(entry.Exit) || ordinaryCredentials[entry.Exit.ClientID] || transit[entry.Exit.ClientID] {
			return nil, ErrXrayCascade
		}
		transit[entry.Exit.ClientID] = true
		ids[entry.ID], tags[inTag], tags[outTag], ports[entry.Port] = true, true, true, true
		tag, flow, err := cascadeService(state, entry.ServiceID)
		if err != nil {
			return nil, err
		}
		original := byTag[tag]
		if original == nil {
			return nil, ErrXrayCascade
		}
		cloned, err := json.Marshal(original)
		if err != nil {
			return nil, err
		}
		var in map[string]any
		if json.Unmarshal(cloned, &in) != nil {
			return nil, ErrXrayCascade
		}
		clients, err := cascadeClients(entry.Clients, flow)
		if err != nil {
			return nil, err
		}
		in["tag"], in["port"] = inTag, entry.Port
		in["settings"] = map[string]any{"clients": clients, "decryption": "none"}
		inbounds = append(inbounds, in)
		endpoint := entry.Exit
		user := map[string]any{"id": endpoint.ClientID, "encryption": "none"}
		if endpoint.Flow != "" {
			user["flow"] = endpoint.Flow
		}
		address := endpoint.Address
		stream := map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": endpoint.ServerName, "fingerprint": endpoint.Fingerprint, "password": endpoint.PublicKey, "shortId": endpoint.ShortID}}
		if endpoint.ConnectRaceAttempts > 0 {
			if !xrayprofile.DialRaceCoreCompatible(state.Core) {
				return nil, ErrXrayCascade
			}
			// A reserved, exact static alias races this explicit IP only.
			// TLS/REALITY identity remains the original endpoint identity.
			address = "pauk-cascade-dial-" + entry.ID + ".invalid"
			dns, ok := cfg["dns"].(map[string]any)
			if cfg["dns"] == nil {
				dns = map[string]any{"servers": []string{"localhost"}}
			} else if !ok {
				return nil, ErrXrayCascade
			}
			hosts, ok := dns["hosts"].(map[string]any)
			if dns["hosts"] == nil {
				hosts = map[string]any{}
			} else if !ok {
				return nil, ErrXrayCascade
			}
			if hosts[address] != nil || hosts["full:"+address] != nil {
				return nil, ErrXrayCascade
			}
			ips := make([]string, endpoint.ConnectRaceAttempts)
			for i := range ips {
				ips[i] = endpoint.ConnectRaceIP
			}
			hosts["full:"+address] = ips
			dns["hosts"] = hosts
			cfg["dns"] = dns
			stream["sockopt"] = map[string]any{"domainStrategy": "ForceIPv4", "happyEyeballs": map[string]any{"tryDelayMs": 100, "maxConcurrentTry": endpoint.ConnectRaceAttempts, "interleave": 1}}
		}
		outbounds = append(outbounds, map[string]any{"tag": outTag, "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": address, "port": endpoint.Port, "users": []any{user}}}}, "streamSettings": stream})
		cascadeRules = append(cascadeRules, map[string]any{"type": "field", "inboundTag": []string{inTag}, "outboundTag": outTag})
	}
	// Both base compilers put the management-port prohibition first. Keep that
	// guard before the cascade route, which precedes any original direct rule.
	guard, ok := rules[0].(map[string]any)
	if !ok || guard["port"] != "10085" {
		return nil, ErrXrayCascade
	}
	routing["rules"] = append(append([]any{rules[0]}, cascadeRules...), rules[1:]...)
	cfg["inbounds"], cfg["outbounds"] = inbounds, outbounds
	return json.MarshalIndent(cfg, "", "  ")
}
