package compiler

import (
	"encoding/json"
	"testing"
	"vpn-platform/internal/model"
)

func TestXrayStatsAreLocalAndUseOpaqueClientKey(t *testing.T) {
	service := model.ServiceSpec{ID: "service-a", Protocol: "vless", Listen: "0.0.0.0", Port: 443, Transport: "tcp", Security: "reality", Reality: &model.RealitySpec{Destination: "example.com:443", ServerName: "example.com", ShortID: "abcd", PrivateKey: "private"}, Clients: []model.ClientSpec{{ID: "credential-secret", StatsKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}}}
	raw, err := CompileXray(model.DesiredState{Services: []model.ServiceSpec{service}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	api := cfg["api"].(map[string]any)
	if api["listen"] != "127.0.0.1:10085" {
		t.Fatal("stats API is not loopback-only")
	}
	rule := cfg["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["port"] != "10085" || rule["outboundTag"] != "BLOCK" || rule["network"] != "tcp,udp" || len(rule) != 4 {
		t.Fatal("management port must be blocked for every proxied destination, including domain names")
	}
	client := cfg["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
	if client["email"] != "client-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@vpn-platform.invalid" || client["email"] == client["id"] {
		t.Fatal("stats identity is not opaque")
	}
	service.Port = 10085
	if _, err = CompileXray(model.DesiredState{Services: []model.ServiceSpec{service}}); err == nil {
		t.Fatal("local API port collision accepted")
	}
}
