package compiler

import (
	"encoding/json"
	"errors"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

func nativeXrayClients(service model.ServiceSpec) ([]map[string]any, error) {
	clients := make([]map[string]any, 0, len(service.Clients))
	for _, client := range service.Clients {
		if client.ID == "" {
			return nil, errors.New("empty Xray client credential")
		}
		field := "id"
		if service.Protocol == "trojan" {
			field = "password"
		}
		entry := map[string]any{field: client.ID}
		if client.StatsKey != "" {
			entry["email"] = "client-" + client.StatsKey + "@vpn-platform.invalid"
			entry["level"] = 0
		}
		clients = append(clients, entry)
	}
	return clients, nil
}

// XrayAuthorizationConfig projects exactly the intended credential objects,
// including cascades, without resolving local Reality keys or certificates.
// It is private authorization data, never a runnable configuration or a log.
func XrayAuthorizationConfig(state model.DesiredState) ([]byte, error) {
	var inbounds []any
	if state.XrayProfile != nil {
		raw, err := xrayprofile.AuthorizationConfig(state.XrayProfile, state.Services)
		if err != nil {
			return nil, err
		}
		var cfg map[string]any
		if json.Unmarshal(raw, &cfg) != nil {
			return nil, ErrXrayCascade
		}
		inbounds = cfg["inbounds"].([]any)
		ports := map[string]int{}
		for _, b := range state.XrayProfile.Bindings {
			for _, s := range state.Services {
				if s.ID == b.ServiceID {
					ports[b.InboundTag] = s.Port
				}
			}
		}
		for _, value := range inbounds {
			in := value.(map[string]any)
			in["port"] = ports[in["tag"].(string)]
		}
	} else {
		inbounds = []any{}
		for _, s := range state.Services {
			var in map[string]any
			var err error
			switch s.Protocol {
			case "vless", "trojan":
				var clients []map[string]any
				clients, err = nativeXrayClients(s)
				in = map[string]any{"tag": s.ID, "port": s.Port, "protocol": s.Protocol, "settings": map[string]any{"clients": clients}}
			case "wireguard":
				in, err = wireguardInbound(s)
			case "shadowsocks":
				in, err = shadowsocksInbound(s)
			default:
				return nil, errors.New("unsupported Xray authorization protocol")
			}
			if err != nil {
				return nil, err
			}
			if in != nil {
				inbounds = append(inbounds, in)
			}
		}
	}
	// Use the same overlay validation and credential constructors as compilation.
	// This skeleton has no streams, private keys, certificates or native routing.
	base, err := json.Marshal(map[string]any{"inbounds": inbounds, "outbounds": []any{}, "routing": map[string]any{"rules": []any{map[string]any{"port": "10085"}}}})
	if err != nil {
		return nil, err
	}
	projected, err := compileXrayCascades(base, state)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if json.Unmarshal(projected, &cfg) != nil {
		return nil, ErrXrayCascade
	}
	result := []any{}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		settings := in["settings"].(map[string]any)
		credentials := map[string]any{}
		for _, name := range []string{"clients", "peers"} {
			if v, exists := settings[name]; exists {
				credentials[name] = v
			}
		}
		result = append(result, map[string]any{"tag": in["tag"], "protocol": in["protocol"], "settings": credentials})
	}
	return json.Marshal(map[string]any{"inbounds": result})
}
