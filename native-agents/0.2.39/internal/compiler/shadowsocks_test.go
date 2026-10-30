package compiler

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"vpn-platform/internal/model"
)

func TestShadowsocksFailsClosed(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	s := model.ServiceSpec{ID: "ss-test", Listen: "127.0.0.1", Port: 8388, Protocol: "shadowsocks", Transport: "tcp,udp", Security: "shadowsocks", Shadowsocks: &model.ShadowsocksSpec{Method: model.ShadowsocksMethod, ServerKey: key}}
	data, err := CompileXray(model.DesiredState{Services: []model.ServiceSpec{s}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []any `json:"inbounds"`
	}
	if err = json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 0 {
		t.Fatal("zero clients must close listener")
	}
	s.Clients = []model.ClientSpec{{ID: key}}
	if _, err = CompileXray(model.DesiredState{Services: []model.ServiceSpec{s}}); err == nil {
		t.Fatal("shared server key accepted as client")
	}
	s.Clients = []model.ClientSpec{{ID: "not-a-key"}}
	if _, err = CompileXray(model.DesiredState{Services: []model.ServiceSpec{s}}); err == nil {
		t.Fatal("invalid key accepted")
	}
	s.Clients = nil
	s.Shadowsocks.Method = "none"
	if _, err = CompileXray(model.DesiredState{Services: []model.ServiceSpec{s}}); err == nil {
		t.Fatal("unencrypted method accepted")
	}
}
