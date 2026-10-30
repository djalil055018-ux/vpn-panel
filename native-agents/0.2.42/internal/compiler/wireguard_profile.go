package compiler

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"vpn-platform/internal/model"
)

func WireGuardProfile(privateKey, serverPublic, presharedKey, address, endpoint string, port int) (string, error) {
	if !model.ValidShadowsocksKey(privateKey) || !model.ValidShadowsocksKey(serverPublic) || !model.ValidShadowsocksKey(presharedKey) || !model.ValidWireGuardAddress(address) || port < 1 || port > 65535 || endpoint == "" || strings.ContainsAny(endpoint, " \t/\\@?#\x00\r\n[]") || (strings.Contains(endpoint, ":") && net.ParseIP(endpoint) == nil) {
		return "", errors.New("invalid WireGuard profile")
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s, %s\nDNS = 1.1.1.1\nMTU = 1420\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", privateKey, address, model.WireGuardIPv6Address(address), serverPublic, presharedKey, net.JoinHostPort(endpoint, strconv.Itoa(port))), nil
}
