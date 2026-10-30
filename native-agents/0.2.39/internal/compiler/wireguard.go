package compiler

import (
	"errors"
	"vpn-platform/internal/model"
)

func wireguardInbound(s model.ServiceSpec) (map[string]any, error) {
	if s.Transport != "udp" || s.Security != "wireguard" || s.WireGuard == nil || !model.ValidShadowsocksKey(s.WireGuard.PrivateKey) {
		return nil, errors.New("WireGuard requires native UDP and a private key")
	}
	serverPublic, err := model.WireGuardPublicKey(s.WireGuard.PrivateKey)
	if err != nil {
		return nil, err
	}
	peers := make([]map[string]any, 0, len(s.Clients))
	keys := map[string]bool{}
	addresses := map[string]bool{}
	for _, c := range s.Clients {
		p := c.WireGuard
		if p == nil || !model.ValidShadowsocksKey(p.PublicKey) || !model.ValidShadowsocksKey(p.PresharedKey) || p.PublicKey == serverPublic || !model.ValidWireGuardAddress(p.Address) || keys[p.PublicKey] || addresses[p.Address] {
			return nil, errors.New("invalid or duplicate WireGuard peer")
		}
		keys[p.PublicKey] = true
		addresses[p.Address] = true
		peer := map[string]any{"publicKey": p.PublicKey, "preSharedKey": p.PresharedKey, "allowedIPs": []string{p.Address, model.WireGuardIPv6Address(p.Address)}, "level": 0}
		if c.StatsKey != "" {
			peer["email"] = "client-" + c.StatsKey + "@vpn-platform.invalid"
		}
		peers = append(peers, peer)
	}
	if len(peers) == 0 {
		return nil, nil
	}
	return map[string]any{"tag": s.ID, "listen": s.Listen, "port": s.Port, "protocol": "wireguard", "settings": map[string]any{"secretKey": s.WireGuard.PrivateKey, "peers": peers, "mtu": 1420}}, nil
}
