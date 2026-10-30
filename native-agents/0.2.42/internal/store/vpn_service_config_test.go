package store

import (
	"errors"
	"testing"
)

func TestValidateVPNServiceTransport(t *testing.T) {
	tests := []struct {
		name, protocol, security, current, requested string
		wantErr                                      error
	}{
		{name: "OpenVPN UDP to TCP", protocol: "openvpn", security: "tls", current: "udp", requested: "tcp"},
		{name: "OpenVPN TCP to UDP", protocol: "openvpn", security: "tls", current: "tcp", requested: "udp"},
		{name: "invalid OpenVPN value", protocol: "openvpn", security: "tls", current: "udp", requested: "sctp", wantErr: ErrVPNServiceTransportInvalid},
		{name: "VLESS TLS TCP to WebSocket", protocol: "vless", security: "tls", current: "tcp", requested: "ws"},
		{name: "VLESS TLS XHTTP to gRPC", protocol: "vless", security: "tls", current: "xhttp", requested: "grpc"},
		{name: "unchanged VLESS REALITY transport", protocol: "vless", security: "reality", current: "tcp", requested: "tcp"},
		{name: "VLESS REALITY transport is immutable", protocol: "vless", security: "reality", current: "tcp", requested: "grpc", wantErr: ErrVPNServiceTransportImmutable},
		{name: "VLESS TLS rejects unknown transport", protocol: "vless", security: "tls", current: "tcp", requested: "sctp", wantErr: ErrVPNServiceTransportInvalid},
		{name: "Trojan transport is managed by protocol settings", protocol: "trojan", security: "tls", current: "tcp", requested: "ws", wantErr: ErrVPNServiceTransportImmutable},
		{name: "omitted transport is preserved", protocol: "shadowsocks", security: "shadowsocks", current: "tcp,udp", requested: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVPNServiceTransport(tt.protocol, tt.security, tt.current, tt.requested)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validation error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}

func TestRequiredAgentForVLESSTLSTransport(t *testing.T) {
	tests := map[string]string{
		"tcp":   "0.2.15",
		"xhttp": "0.2.17",
		"ws":    "0.2.26",
		"grpc":  "0.2.26",
		"udp":   "",
	}
	for transport, want := range tests {
		t.Run(transport, func(t *testing.T) {
			if got := requiredAgentForVLESSTLSTransport(transport); got != want {
				t.Fatalf("required agent = %q; want %q", got, want)
			}
		})
	}
}
