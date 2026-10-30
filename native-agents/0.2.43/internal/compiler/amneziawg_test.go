package compiler

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

func TestAmneziaWGServerAndClientDialects(t *testing.T) {
	key := func() string {
		var b [32]byte
		if _, e := rand.Read(b[:]); e != nil {
			t.Fatal(e)
		}
		return base64.StdEncoding.EncodeToString(b[:])
	}
	server, client, psk := key(), key(), key()
	serverPublic, e := model.WireGuardPublicKey(server)
	if e != nil {
		t.Fatal(e)
	}
	clientPublic, e := model.WireGuardPublicKey(client)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"1.0", "1.5", "2.0", "3.0", "3.1"} {
		t.Run(v, func(t *testing.T) {
			spec, e := model.NewAmneziaWGSpec(v)
			if e != nil {
				t.Fatal(e)
			}
			service := model.ServiceSpec{Protocol: "amneziawg", Transport: "udp", Security: "amneziawg", Listen: "0.0.0.0", Port: 51821, WireGuard: &model.WireGuardSpec{PrivateKey: server}, AmneziaWG: spec, Clients: []model.ClientSpec{{WireGuard: &model.WireGuardPeer{PublicKey: clientPublic, PresharedKey: psk, Address: "10.66.0.2/32"}}}}
			config, e := CompileAmneziaWG(service)
			if e != nil {
				t.Fatal(e)
			}
			profile, e := AmneziaWGProfile(client, serverPublic, psk, "10.66.0.2/32", "vpn.example", 51821, *spec)
			if e != nil {
				t.Fatal(e)
			}
			lines, e := spec.ConfigLines()
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(string(config), lines) || !strings.Contains(profile, lines) {
				t.Fatal("server and client parameters differ")
			}
			if strings.Contains(profile, server) || strings.Contains(profile, clientPublic) {
				t.Fatal("wrong credential in client profile")
			}
			if !strings.Contains(profile, "MTU = 1280\n") || !strings.Contains(profile, "AllowedIPs = 0.0.0.0/0, ::/0") {
				t.Fatal("client routes or MTU missing")
			}
			uapi, e := AmneziaWGUAPI(service)
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(string(uapi), "replace_peers=true\n") || !strings.Contains(string(uapi), "allowed_ip=10.66.0.2/32\n") || strings.Contains(string(uapi), server) {
				t.Fatal("invalid runtime control configuration")
			}
			if v == "3.1" && !strings.Contains(string(uapi), "random_trailers=true\n") {
				t.Fatal("3.1 option missing")
			}
			wrong := service
			wrong.Protocol = "wireguard"
			wrong.Security = "wireguard"
			if _, e := wireguardInbound(wrong); e == nil {
				t.Fatal("Xray silently accepted unsupported AmneziaWG settings")
			}
			wrong = service
			wrong.Clients[0].WireGuard.Address = "10.99.0.2/32"
			if _, e := CompileAmneziaWG(wrong); e == nil {
				t.Fatal("out-of-pool peer accepted")
			}
		})
	}
}
