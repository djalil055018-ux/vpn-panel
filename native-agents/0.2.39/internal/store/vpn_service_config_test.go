package store

import (
	"errors"
	"testing"
)

func TestValidateVPNServiceTransport(t *testing.T) {
	tests := []struct {
		name, protocol, current, requested string
		wantErr                            error
	}{
		{name: "OpenVPN UDP to TCP", protocol: "openvpn", current: "udp", requested: "tcp"},
		{name: "OpenVPN TCP to UDP", protocol: "openvpn", current: "tcp", requested: "udp"},
		{name: "invalid OpenVPN value", protocol: "openvpn", current: "udp", requested: "sctp", wantErr: ErrVPNServiceTransportInvalid},
		{name: "unchanged non-OpenVPN transport", protocol: "vless", current: "tcp", requested: "tcp"},
		{name: "non-OpenVPN transport is immutable", protocol: "vless", current: "tcp", requested: "grpc", wantErr: ErrVPNServiceTransportImmutable},
		{name: "omitted transport is preserved", protocol: "shadowsocks", current: "tcp,udp", requested: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVPNServiceTransport(tt.protocol, tt.current, tt.requested)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validation error = %v; want %v", err, tt.wantErr)
			}
		})
	}
}
