package compiler

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"vpn-platform/internal/model"
)

// CompileKernelWireGuard returns wg setconf input, never wg-quick hooks.
// Interface addresses, routes and firewall policy belong to the managed driver.
// Linux WireGuard listens on all local addresses; a narrower bind request must
// not silently become an all-address listener.
func CompileKernelWireGuard(s model.ServiceSpec) ([]byte, error) {
	if s.Protocol != "wireguard" || s.Port < 1 || s.Port > 65535 || (s.Listen != "0.0.0.0" && s.Listen != "::") {
		return nil, errors.New("native WireGuard requires a valid UDP port and wildcard listen address")
	}
	if _, err := wireguardInbound(s); err != nil {
		return nil, err
	}
	pool := netip.MustParsePrefix("10.66.0.0/16")
	for _, client := range s.Clients {
		prefix, err := netip.ParsePrefix(client.WireGuard.Address)
		if err != nil || !pool.Contains(prefix.Addr()) || client.WireGuard.Address == "10.66.0.1/32" {
			return nil, errors.New("native WireGuard peer address conflicts with managed network")
		}
	}
	peers := append([]model.ClientSpec(nil), s.Clients...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].WireGuard.PublicKey < peers[j].WireGuard.PublicKey })
	var out strings.Builder
	fmt.Fprintf(&out, "[Interface]\nPrivateKey = %s\nListenPort = %d\n", s.WireGuard.PrivateKey, s.Port)
	for _, client := range peers {
		peer := client.WireGuard
		fmt.Fprintf(&out, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s, %s\n", peer.PublicKey, peer.PresharedKey, peer.Address, model.WireGuardIPv6Address(peer.Address))
	}
	return []byte(out.String()), nil
}
