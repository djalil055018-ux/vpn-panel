package compiler

import (
	"encoding/base64"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

func kernelFixture() model.ServiceSpec {
	key := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	server := key(strings.Repeat("s", 32))
	public, _ := model.WireGuardPublicKey(key(strings.Repeat("c", 32)))
	return model.ServiceSpec{Protocol: "wireguard", Transport: "udp", Security: "wireguard", Listen: "0.0.0.0", Port: 51820, WireGuard: &model.WireGuardSpec{PrivateKey: server}, Clients: []model.ClientSpec{{WireGuard: &model.WireGuardPeer{PublicKey: public, PresharedKey: server, Address: "10.66.0.2/32"}}}}
}
func TestKernelWireGuardRejectsUnsafeConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*model.ServiceSpec){
		"narrow-listen":  func(s *model.ServiceSpec) { s.Listen = "127.0.0.1" },
		"port":           func(s *model.ServiceSpec) { s.Port = 65536 },
		"wrong-protocol": func(s *model.ServiceSpec) { s.Protocol = "vless" },
		"injected-key":   func(s *model.ServiceSpec) { s.WireGuard.PrivateKey += "\nPostUp = false" },
		"duplicate-peer": func(s *model.ServiceSpec) { s.Clients = append(s.Clients, s.Clients[0]) },
		"gateway":        func(s *model.ServiceSpec) { s.Clients[0].WireGuard.Address = "10.66.0.1/32" },
		"outside-pool":   func(s *model.ServiceSpec) { s.Clients[0].WireGuard.Address = "172.17.0.1/32" },
		"wide-route":     func(s *model.ServiceSpec) { s.Clients[0].WireGuard.Address = "10.66.0.0/24" },
		"missing-peer":   func(s *model.ServiceSpec) { s.Clients[0].WireGuard = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := kernelFixture()
			mutate(&s)
			if _, err := CompileKernelWireGuard(s); err == nil {
				t.Fatal("unsafe native configuration accepted")
			}
		})
	}
}
func TestKernelWireGuardConfiguration(t *testing.T) {
	s := kernelFixture()
	raw, err := CompileKernelWireGuard(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "AllowedIPs = 10.66.0.2/32, fd66::a42:2/128") || strings.Contains(string(raw), "PostUp") {
		t.Fatal("incorrect native configuration")
	}
	s.Clients = nil
	raw, err = CompileKernelWireGuard(s)
	if err != nil || strings.Contains(string(raw), "[Peer]") {
		t.Fatal("empty state must not preserve peers")
	}
}
