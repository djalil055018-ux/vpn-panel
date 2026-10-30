// Synthetic-only configuration generator for the isolated Linux tunnel test.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
)

func main() {
	dir := flag.String("output-dir", "", "new private synthetic fixture directory")
	flag.Parse()
	if *dir == "" {
		panic("output directory required")
	}
	if e := os.Mkdir(*dir, 0700); e != nil {
		panic("fixture directory must be new")
	}
	key := func() string {
		var b [32]byte
		if _, e := rand.Read(b[:]); e != nil {
			panic("random source unavailable")
		}
		return base64.StdEncoding.EncodeToString(b[:])
	}
	rows := []map[string]string{}
	for _, v := range []string{"wireguard", "1.0", "1.5", "2.0", "3.0", "3.1"} {
		server, client, psk := key(), key(), key()
		sp, e := model.WireGuardPublicKey(server)
		if e != nil {
			panic("invalid synthetic key")
		}
		cp, e := model.WireGuardPublicKey(client)
		if e != nil {
			panic("invalid synthetic key")
		}
		service := model.ServiceSpec{Protocol: "wireguard", Transport: "udp", Security: "wireguard", Listen: "0.0.0.0", Port: 51821, WireGuard: &model.WireGuardSpec{PrivateKey: server}, Clients: []model.ClientSpec{{WireGuard: &model.WireGuardPeer{PublicKey: cp, PresharedKey: psk, Address: "10.66.0.2/32"}}}}
		var config []byte
		var profile string
		if v == "wireguard" {
			config, e = compiler.CompileKernelWireGuard(service)
			if e == nil {
				profile, e = compiler.WireGuardProfile(client, sp, psk, "10.66.0.2/32", "192.0.2.1", 51821)
			}
		} else {
			service.Protocol = "amneziawg"
			service.Security = "amneziawg"
			service.AmneziaWG, e = model.NewAmneziaWGSpec(v)
			if e == nil {
				config, e = compiler.CompileAmneziaWG(service)
			}
			if e == nil {
				profile, e = compiler.AmneziaWGProfile(client, sp, psk, "10.66.0.2/32", "192.0.2.1", 51821, *service.AmneziaWG)
			}
		}
		if e != nil {
			panic("synthetic configuration rejected")
		}
		name := strings.ReplaceAll(v, ".", "_")
		serverName := name + "-server.conf"
		clientName := name + "-client.conf"
		emptyName := name + "-empty.conf"
		service.Clients = nil
		var empty []byte
		if v == "wireguard" {
			empty, e = compiler.CompileKernelWireGuard(service)
		} else {
			empty, e = compiler.CompileAmneziaWG(service)
		}
		if e != nil {
			panic("empty configuration rejected")
		}
		for name, data := range map[string][]byte{serverName: config, clientName: []byte(profile), emptyName: empty} {
			if os.WriteFile(filepath.Join(*dir, name), data, 0600) != nil {
				panic("fixture write failed")
			}
		}
		rows = append(rows, map[string]string{"version": v, "server": serverName, "client": clientName, "empty": emptyName})
	}
	data, e := json.Marshal(rows)
	if e != nil {
		panic("metadata failed")
	}
	if os.WriteFile(filepath.Join(*dir, "manifest.json"), data, 0600) != nil {
		panic("manifest write failed")
	}
	fmt.Println("SYNTHETIC_CONFIGURATIONS=6")
}
