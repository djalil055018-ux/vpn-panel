package compiler

import (
	"encoding/json"
	"testing"
	"vpn-platform/internal/model"
)

func TestXHTTPTLSCompileAndUnsupportedCombinations(t *testing.T) {
	s := model.ServiceSpec{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Protocol: "vless", Listen: "127.0.0.1", Port: 8443, Transport: "xhttp", Security: "tls", Clients: []model.ClientSpec{{ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}}, TLS: &model.TLSSpec{ServerName: "test.example", CertificateFile: "/cert.pem", KeyFile: "/key.pem"}}
	raw, err := CompileXray(model.DesiredState{Services: []model.ServiceSpec{s}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			Stream map[string]any `json:"streamSettings"`
		}
	}
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("invalid config")
	}
	stream := cfg.Inbounds[0].Stream
	x := stream["xhttpSettings"].(map[string]any)
	if stream["network"] != "xhttp" || x["path"] != "/vpn/"+s.ID || x["mode"] != "auto" {
		t.Fatal("XHTTP config mismatch")
	}
	for _, mutate := range []func(*model.ServiceSpec){func(v *model.ServiceSpec) { v.Protocol = "trojan" }, func(v *model.ServiceSpec) { v.Security = "none" }, func(v *model.ServiceSpec) { v.Security = "reality" }, func(v *model.ServiceSpec) { v.ID = "../../unsafe" }} {
		copy := s
		mutate(&copy)
		if _, err := CompileXray(model.DesiredState{Services: []model.ServiceSpec{copy}}); err == nil {
			t.Fatal("unsupported XHTTP combination accepted")
		}
	}
}
