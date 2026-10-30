package compiler

import (
	"errors"
	"vpn-platform/internal/model"
)

func shadowsocksInbound(service model.ServiceSpec) (map[string]any, error) {
	if service.Transport != "tcp,udp" || service.Security != "shadowsocks" || service.Shadowsocks == nil || service.Shadowsocks.Method != model.ShadowsocksMethod || !model.ValidShadowsocksKey(service.Shadowsocks.ServerKey) {
		return nil, errors.New("Shadowsocks requires native TCP/UDP and valid AEAD-2022 keys")
	}
	users := make([]map[string]any, 0, len(service.Clients))
	seen := make(map[string]bool)
	for _, client := range service.Clients {
		if !model.ValidShadowsocksKey(client.ID) || client.ID == service.Shadowsocks.ServerKey || seen[client.ID] {
			return nil, errors.New("invalid or duplicate Shadowsocks client key")
		}
		seen[client.ID] = true
		user := map[string]any{"password": client.ID, "level": 0}
		if client.StatsKey != "" {
			user["email"] = "client-" + client.StatsKey + "@vpn-platform.invalid"
		}
		users = append(users, user)
	}
	// An empty users array can select single-user mode in core versions. Close
	// the listener instead, so the shared server key never grants client access.
	if len(users) == 0 {
		return nil, nil
	}
	return map[string]any{"tag": service.ID, "listen": service.Listen, "port": service.Port, "protocol": "shadowsocks", "settings": map[string]any{"network": "tcp,udp", "method": model.ShadowsocksMethod, "password": service.Shadowsocks.ServerKey, "clients": users}}, nil
}
