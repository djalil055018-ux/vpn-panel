package xrayprofile

import (
	"encoding/json"

	"vpn-platform/internal/model"
)

func clientFlow(in map[string]any) string {
	stream := in["streamSettings"].(map[string]any)
	settings := in["settings"].(map[string]any)
	flow := ""
	if str(in["protocol"]) == "vless" {
		if explicit, exists := settings["flow"]; exists {
			if str(explicit) == "xtls-rprx-vision" {
				flow = "xtls-rprx-vision"
			}
		} else if oneOf(stream["network"], "raw", "tcp") {
			flow = "xtls-rprx-vision"
		}
	}
	return flow
}

// VLESSFlow uses the reviewed source template even when a service currently has
// no authorized clients. A cascade cannot infer flow from the first user.
func VLESSFlow(spec *model.XrayProfileSpec, serviceID string) (string, error) {
	cfg, bindings, err := parse(spec)
	if err != nil {
		return "", err
	}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		if bindings[str(in["tag"])] == serviceID && str(in["protocol"]) == "vless" {
			return clientFlow(in), nil
		}
	}
	return "", ErrProfile
}

func authorizedClients(in map[string]any, service model.ServiceSpec) []any {
	flow := clientFlow(in)
	clients := []any{}
	for _, client := range service.Clients {
		entry := map[string]any{"email": "client-" + client.StatsKey + "@vpn-platform.invalid", "level": 0}
		if str(in["protocol"]) == "hysteria" {
			entry["auth"] = client.ID
		} else {
			entry["id"] = client.ID
			if flow != "" {
				entry["flow"] = flow
			}
		}
		clients = append(clients, entry)
	}
	return clients
}

// AuthorizationConfig is the intended native credential set without server
// keys/certificates. The agent can detect revocation before install, local secret
// resolution or native validation, and close access if those later steps fail.
// This document is internal and contains client credentials: never log it.
func AuthorizationConfig(spec *model.XrayProfileSpec, services []model.ServiceSpec) ([]byte, error) {
	cfg, bindings, err := parse(spec)
	if err != nil {
		return nil, err
	}
	byID, err := serviceMap(cfg, bindings, services)
	if err != nil {
		return nil, err
	}
	inbounds := []any{}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		service, enabled := byID[bindings[str(in["tag"])]]
		if !enabled {
			continue
		}
		inbounds = append(inbounds, map[string]any{"tag": in["tag"], "protocol": in["protocol"], "settings": map[string]any{"clients": authorizedClients(in, service)}})
	}
	return json.Marshal(map[string]any{"inbounds": inbounds})
}
