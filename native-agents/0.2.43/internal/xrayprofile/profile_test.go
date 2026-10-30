package xrayprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"vpn-platform/internal/model"
)

func fixture(t *testing.T) ([]byte, []model.XrayProfileBinding, []model.ServiceSpec) {
	t.Helper()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	inbounds := []any{}
	bindings := []model.XrayProfileBinding{}
	services := []model.ServiceSpec{}
	for i, kind := range []string{"raw", "grpc", "xhttp", "hysteria"} {
		id := fmt.Sprintf("11111111-1111-4111-8111-%012d", i+1)
		tag := "imported-" + kind
		port := []int{443, 8443, 4443, 443}[i]
		bindings = append(bindings, model.XrayProfileBinding{ServiceID: id, InboundTag: tag})
		protocol, transport, security := "vless", kind, "reality"
		settings := map[string]any{"clients": []any{}, "decryption": "none"}
		stream := map[string]any{"network": kind, "security": "reality", "realitySettings": map[string]any{
			"dest": "example.org:443", "serverNames": []string{"example.org"}, "shortIds": []string{""}, "privateKey": key, "show": false, "spiderX": "", "xver": 0,
		}}
		if kind == "raw" {
			transport = "tcp"
			r := stream["realitySettings"].(map[string]any)
			delete(r, "dest")
			r["target"] = "/run/imported-front/tls.sock"
			r["xver"] = 1
		}
		if kind == "grpc" {
			stream["grpcSettings"] = map[string]any{"serviceName": "original-grpc", "multiMode": true}
		}
		if kind == "xhttp" {
			stream["xhttpSettings"] = map[string]any{"path": "/original-xhttp", "mode": "auto", "noGRPCHeader": true, "scMaxBufferedPosts": 30, "scMaxEachPostBytes": "1000-2000", "xPaddingBytes": "100-1000"}
		}
		if kind == "hysteria" {
			protocol, transport, security = "hysteria", "udp", "tls"
			settings = map[string]any{"clients": []any{}, "version": 2}
			stream = map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2},
				"finalmask":   map[string]any{"quicParams": map[string]any{"congestion": "bbr", "debug": false}},
				"tlsSettings": map[string]any{"alpn": []string{"h3"}, "certificates": []any{map[string]any{"certificateFile": "/source/private/fullchain.pem", "keyFile": "/source/private/privkey.pem"}}},
			}
		}
		in := map[string]any{"tag": tag, "listen": "0.0.0.0", "port": port, "protocol": protocol, "settings": settings, "streamSettings": stream}
		if kind != "hysteria" {
			in["sniffing"] = map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}}
		}
		inbounds = append(inbounds, in)
		if protocol == "hysteria" {
			protocol = "hysteria2"
		}
		service := model.ServiceSpec{ID: id, Protocol: protocol, Listen: "0.0.0.0", Port: port, Transport: transport, Security: security,
			Clients: []model.ClientSpec{{ID: "22222222-2222-4222-8222-222222222222", StatsKey: "33333333-3333-4333-8333-333333333333"}},
		}
		if security == "reality" {
			service.Reality = &model.RealitySpec{Destination: "example.org:443", ServerName: "example.org", ShortID: "", SecretRef: "reality/" + id, PrivateKey: key}
			if kind == "raw" {
				service.Reality.Destination = "/run/imported-front/tls.sock"
			}
		} else {
			service.TLS = &model.TLSSpec{CertificateID: id, ServerName: "example.org", CertificateFile: "/runtime/cert.pem", KeyFile: "/runtime/key.pem"}
		}
		services = append(services, service)
	}
	cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}, "dns": map[string]any{"servers": []string{"1.1.1.1"}},
		"inbounds": inbounds, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}, map[string]any{"tag": "BLOCK", "protocol": "blackhole"}, map[string]any{"tag": "TUNNEL", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIPv4"}, "streamSettings": map[string]any{"sockopt": map[string]any{"interface": "wg0", "tcpFastOpen": true}}}},
		"routing": map[string]any{"rules": []any{map[string]any{"ip": []string{"geoip:private"}, "outboundTag": "BLOCK"}, map[string]any{"domain": []string{"domain:example.com"}, "outboundTag": "TUNNEL"}}},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal("fixture encoding")
	}
	return raw, bindings, services
}

func TestImportedProfilePreservesGraph(t *testing.T) {
	raw, bindings, services := fixture(t)
	before := append([]byte(nil), raw...)
	spec, local, err := Project(raw, bindings)
	if err != nil || ValidateServices(spec, services) != nil {
		t.Fatal("projection or validation")
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("projection changed input")
	}
	dependencies, err := RequiredDependencies(spec)
	if err != nil || !reflect.DeepEqual(dependencies.UnixSockets, []string{"/run/imported-front/tls.sock"}) || !reflect.DeepEqual(dependencies.Interfaces, []string{"wg0"}) {
		t.Fatal("external runtime dependency omitted")
	}
	wire, _ := json.Marshal(spec)
	localWire, _ := json.Marshal(local)
	for _, secret := range []string{services[0].Reality.PrivateKey, "/source/private", "/runtime/cert.pem", "22222222-2222-4222-8222-222222222222"} {
		if bytes.Contains(wire, []byte(secret)) || bytes.Contains(localWire, []byte(secret)) {
			t.Fatal("private material in serialized projection")
		}
	}
	serialized := append([]byte(nil), wire...)
	config, err := Compile(spec, services)
	if err != nil {
		t.Fatal("compile")
	}
	wire, _ = json.Marshal(spec)
	if !bytes.Equal(serialized, wire) {
		t.Fatal("compile changed shared profile")
	}
	original, _ := decode(raw)
	actual, _ := decode(config)
	for _, field := range []string{"log", "dns"} {
		if !reflect.DeepEqual(original[field], actual[field]) {
			t.Fatal("global field changed")
		}
	}
	outs := actual["outbounds"].([]any)
	if !reflect.DeepEqual(original["outbounds"], outs[:len(outs)-1]) {
		t.Fatal("outbound order or settings changed")
	}
	rules := actual["routing"].(map[string]any)["rules"].([]any)
	if !reflect.DeepEqual(original["routing"].(map[string]any)["rules"], rules[1:]) {
		t.Fatal("source routing changed")
	}
	guard := rules[0].(map[string]any)
	if guard["port"] != "10085" || guard["outboundTag"] != blockTag {
		t.Fatal("local management guard missing")
	}
	for i, value := range actual["inbounds"].([]any) {
		in := value.(map[string]any)
		old := original["inbounds"].([]any)[i].(map[string]any)
		settings := in["settings"].(map[string]any)
		client := settings["clients"].([]any)[0].(map[string]any)
		if client["email"] != "client-33333333-3333-4333-8333-333333333333@vpn-platform.invalid" {
			t.Fatal("traffic identity mismatch")
		}
		if i == 0 && client["flow"] != "xtls-rprx-vision" {
			t.Fatal("RAW Vision compatibility lost")
		}
		if i > 0 && client["flow"] != nil {
			t.Fatal("flow added to non-RAW transport")
		}
		field := "id"
		if i == 3 {
			field = "auth"
		}
		if client[field] != services[i].Clients[0].ID {
			t.Fatal("credential mapping")
		}
		settings["clients"] = []any{}
		if i == 3 {
			in["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["certificates"] = old["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["certificates"]
		}
		if !reflect.DeepEqual(in, old) {
			t.Fatal("source inbound settings changed")
		}
	}
}

func TestImportedProfileRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	cases := map[string]func(map[string]any){
		"unknown-root": func(c map[string]any) { c["api"] = map[string]any{"listen": "0.0.0.0:10085"} },
		"embedded-client": func(c map[string]any) {
			first(c)["settings"].(map[string]any)["clients"] = []any{map[string]any{"id": "secret"}}
		},
		"unmanaged-users": func(c map[string]any) { first(c)["settings"].(map[string]any)["users"] = []any{} },
		"fallback-auth": func(c map[string]any) {
			c["inbounds"].([]any)[3].(map[string]any)["streamSettings"].(map[string]any)["hysteriaSettings"].(map[string]any)["auth"] = "secret"
		},
		"management-port": func(c map[string]any) { first(c)["port"] = json.Number("10085") },
		"unknown-stream":  func(c map[string]any) { first(c)["streamSettings"].(map[string]any)["sockopt"] = map[string]any{} },
		"bad-key": func(c map[string]any) {
			first(c)["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["privateKey"] = "bad"
		},
		"unknown-routing": func(c map[string]any) {
			c["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)["outboundTag"] = "MISSING"
		},
		"unknown-outbound":   func(c map[string]any) { c["outbounds"].([]any)[0].(map[string]any)["protocol"] = "socks" },
		"duplicate-listener": func(c map[string]any) { c["inbounds"].([]any)[1].(map[string]any)["port"] = json.Number("443") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw, bindings, _ := fixture(t)
			cfg, _ := decode(raw)
			mutate(cfg)
			raw, _ = json.Marshal(cfg)
			if _, _, err := Project(raw, bindings); err == nil {
				t.Fatal("unsafe source accepted")
			}
		})
	}
	raw, bindings, _ := fixture(t)
	for _, malformed := range [][]byte{append(raw, []byte("{}")...), []byte(`{"a":{"x":1,"x":2}}`), {0xff}, []byte("null")} {
		if _, _, err := Project(malformed, bindings); err == nil {
			t.Fatal("ambiguous document accepted")
		}
	}
}
func first(cfg map[string]any) map[string]any { return cfg["inbounds"].([]any)[0].(map[string]any) }

func TestImportedProfileIdentityAndRevocation(t *testing.T) {
	raw, bindings, services := fixture(t)
	spec, _, err := Project(raw, bindings)
	if err != nil {
		t.Fatal("project")
	}
	tampered := *spec
	tampered.Bindings = append([]model.XrayProfileBinding(nil), spec.Bindings...)
	tampered.Bindings[0].ServiceID = "44444444-4444-4444-8444-444444444444"
	if Validate(&tampered) == nil {
		t.Fatal("binding not bound by reviewed digest")
	}
	if _, err := Compile(spec, append(services, services[0])); err == nil {
		t.Fatal("duplicate service accepted")
	}
	r := *services[0].Reality
	r.PrivateKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	wrong := append([]model.ServiceSpec(nil), services...)
	wrong[0].Reality = &r
	if _, err := Compile(spec, wrong); err == nil {
		t.Fatal("replacement server key accepted")
	}
	empty, err := Compile(spec, nil)
	if err != nil {
		t.Fatal("empty compile")
	}
	c, _ := decode(empty)
	if len(c["inbounds"].([]any)) != 0 {
		t.Fatal("disabled listeners retained")
	}
	reduced := append([]model.ServiceSpec(nil), services[:3]...)
	for i := range reduced {
		reduced[i].Clients = nil
	}
	result, err := Compile(spec, reduced)
	if err != nil {
		t.Fatal("revoke compile")
	}
	if strings.Contains(string(result), "22222222-2222-4222-8222-222222222222") || strings.Contains(string(result), `"auth"`) || strings.Contains(string(result), `"protocol": "hysteria"`) {
		t.Fatal("revoked access retained")
	}
}

func TestImportedProfileExplicitFlow(t *testing.T) {
	raw, bindings, services := fixture(t)
	c, _ := decode(raw)
	first(c)["settings"].(map[string]any)["flow"] = "none"
	raw, _ = json.Marshal(c)
	spec, _, err := Project(raw, bindings)
	if err != nil {
		t.Fatal("explicit flow project")
	}
	result, err := Compile(spec, services)
	if err != nil || bytes.Contains(result, []byte("xtls-rprx-vision")) {
		t.Fatal("explicit no-flow override ignored")
	}
}

func TestImportedRevocationIntentDoesNotNeedServerSecrets(t *testing.T) {
	raw, bindings, services := fixture(t)
	spec, _, err := Project(raw, bindings)
	if err != nil {
		t.Fatal("project")
	}
	compiled, err := Compile(spec, services)
	if err != nil {
		t.Fatal("compile")
	}
	var full map[string]any
	json.Unmarshal(compiled, &full)
	// Lose local server material after an existing valid configuration is live.
	for i := range services {
		if services[i].Reality != nil {
			services[i].Reality.PrivateKey = ""
		}
		if services[i].TLS != nil {
			services[i].TLS.KeyFile = ""
			services[i].TLS.CertificateFile = ""
		}
	}
	if _, err := Compile(spec, services); err == nil {
		t.Fatal("compile accepted missing local material")
	}
	intent, err := AuthorizationConfig(spec, services)
	if err != nil {
		t.Fatal("authorization intent requires unavailable server material")
	}
	var auth map[string]any
	json.Unmarshal(intent, &auth)
	for i, value := range auth["inbounds"].([]any) {
		in := value.(map[string]any)
		original := full["inbounds"].([]any)[i].(map[string]any)
		if !reflect.DeepEqual(in["settings"].(map[string]any)["clients"], original["settings"].(map[string]any)["clients"]) {
			t.Fatal("intent differs from actual native authorization")
		}
		if in["streamSettings"] != nil {
			t.Fatal("intent contains server material")
		}
	}
	for i := range services {
		services[i].Clients = nil
	}
	revoked, err := AuthorizationConfig(spec, services)
	if err != nil || bytes.Contains(revoked, []byte("22222222-2222-4222-8222-222222222222")) {
		t.Fatal("revocation intent retains removed credentials")
	}
}
