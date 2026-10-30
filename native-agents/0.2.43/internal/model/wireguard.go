package model

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"net/netip"
)

type WireGuardSpec struct {
	PrivateKey string `json:"private_key"`
}
type WireGuardPeer struct {
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	Address      string `json:"address"`
}

func WireGuardPublicKey(private string) (string, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(private)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func ValidWireGuardAddress(value string) bool {
	p, err := netip.ParsePrefix(value)
	return err == nil && p.Addr().Is4() && p.Bits() == 32 && p.Addr().IsPrivate() && p.String() == value
}

func WireGuardIPv6Address(ipv4 string) string {
	if !ValidWireGuardAddress(ipv4) {
		return ""
	}
	p, _ := netip.ParsePrefix(ipv4)
	b := p.Addr().As4()
	return fmt.Sprintf("fd66::%x:%x/128", uint16(b[0])<<8|uint16(b[1]), uint16(b[2])<<8|uint16(b[3]))
}
