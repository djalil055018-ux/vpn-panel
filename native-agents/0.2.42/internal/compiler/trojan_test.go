package compiler

import (
	"encoding/json"
	"testing"
	"vpn-platform/internal/model"
)

func TestTrojanRequiresTLSAndUsesPasswordAuthentication(t *testing.T) {
	s := model.ServiceSpec{ID: "test-service", Protocol: "trojan", Listen: "127.0.0.1", Port: 18443, Transport: "tcp", Security: "tls", Clients: []model.ClientSpec{{ID: "test-client-credential"}}, TLS: &model.TLSSpec{ServerName: "test.example", CertificateFile: "/certificate.pem", KeyFile: "/private.key"}}
	raw, err := CompileXray(model.DesiredState{Services: []model.ServiceSpec{s}})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	in := config["inbounds"].([]any)[0].(map[string]any)
	settings := in["settings"].(map[string]any)
	client := settings["clients"].([]any)[0].(map[string]any)
	if in["protocol"] != "trojan" || client["password"] != "test-client-credential" || client["id"] != nil || settings["decryption"] != nil {
		t.Fatal("invalid Trojan authentication configuration")
	}
	for _, security := range []string{"none", "reality"} {
		s.Security = security
		if _, err = CompileXray(model.DesiredState{Services: []model.ServiceSpec{s}}); err == nil {
			t.Fatal("Trojan accepted without TLS")
		}
	}
}
