package compiler

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"vpn-platform/internal/model"
)

func hysteriaFixture() (model.DesiredState, HysteriaRuntimeOptions) {
	return model.DesiredState{Core: model.CoreRelease{Type: "hysteria2"}, Services: []model.ServiceSpec{{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Protocol: "hysteria2", Transport: "udp", Listen: "::1", Port: 443, Security: "tls", TLS: &model.TLSSpec{CertificateID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ServerName: "test.invalid", CertificateFile: "/private/fullchain.pem", KeyFile: "/private/key.pem"}, Clients: []model.ClientSpec{{ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", StatsKey: "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}}}}}, HysteriaRuntimeOptions{AuthPort: 10086, StatisticsPort: 10087, StatisticsSecret: strings.Repeat("a", 43)}
}
func TestHysteriaCompilerLocalManagementAndNoClientSecrets(t *testing.T) {
	state, options := hysteriaFixture()
	raw, err := CompileHysteria(state, options)
	if err != nil {
		t.Fatal("valid configuration rejected")
	}
	var config map[string]any
	if json.Unmarshal(raw, &config) != nil || config["listen"] != "[::1]:443" {
		t.Fatal("IPv6 listener encoding failed")
	}
	if strings.Contains(string(raw), state.Services[0].Clients[0].ID) || strings.Contains(string(raw), state.Services[0].Clients[0].StatsKey) {
		t.Fatal("HTTP auth runtime config contains client credentials")
	}
	if config["auth"].(map[string]any)["http"].(map[string]any)["url"] != "http://127.0.0.1:10086/auth" {
		t.Fatal("auth is not node-local")
	}
	rules := config["acl"].(map[string]any)["inline"].([]any)
	if len(rules) != 3 || rules[0] != "reject(all, */10086)" || rules[1] != "reject(all, */10087)" {
		t.Fatal("management proxy destinations unprotected")
	}
	state.Services[0].Clients = nil
	if raw, err = CompileHysteria(state, options); err != nil || raw == nil {
		t.Fatal("empty access set must remain valid HTTP auth config")
	}
	state.Services = nil
	if raw, err = CompileHysteria(state, options); err != nil || raw != nil {
		t.Fatal("no services should request idle runtime")
	}
}
func TestHysteriaCompilerRejectsUnsupportedOrUnsafeState(t *testing.T) {
	for _, mutate := range []func(*model.DesiredState, *HysteriaRuntimeOptions){
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { s.Core.Type = "xray" },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { s.Services = append(s.Services, s.Services[0]) },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { s.Services[0].Protocol = "vless" },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { s.Services[0].Security = "none" },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { s.Services[0].Listen = "example.com" },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { s.Services[0].Port = o.AuthPort },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { s.Services[0].TLS.KeyFile = "../private.key" },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) {
			s.Services[0].Clients = append(s.Services[0].Clients, s.Services[0].Clients[0])
		},
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { s.Services[0].Clients[0].StatsKey = "missing" },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) {
			s.Services[0].Clients[0].StatsKey = strings.ToUpper(s.Services[0].Clients[0].StatsKey)
		},
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { o.StatisticsSecret = "short" },
		func(s *model.DesiredState, o *HysteriaRuntimeOptions) { o.AuthPort = o.StatisticsPort },
	} {
		s, o := hysteriaFixture()
		mutate(&s, &o)
		raw, err := CompileHysteria(s, o)
		if err != ErrHysteriaConfig || raw != nil {
			t.Fatal("unsupported or unsafe config accepted")
		}
	}
}

func TestHysteriaDistributedMetadataNeedsLocalResolution(t *testing.T) {
	state, options := hysteriaFixture()
	state.Services[0].TLS.CertificateFile = ""
	state.Services[0].TLS.KeyFile = ""
	if err := ValidateHysteriaDesired(state); err != nil {
		t.Fatal("distributed metadata requires node-private certificate paths")
	}
	if _, err := CompileHysteria(state, options); err == nil {
		t.Fatal("native config accepted unresolved certificate paths")
	}
	state.Services[0].TLS.ServerName = "test.invalid?insecure=1"
	if err := ValidateHysteriaDesired(state); err == nil {
		t.Fatal("invalid distributed SNI accepted")
	}
}

func TestHysteriaSubscriptionURI(t *testing.T) {
	c := model.VPNClientConnection{Protocol: "hysteria2", Transport: "udp", Security: "tls", UUID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Address: "2001:db8::1", Port: 8443, ServerName: "test.invalid", ServiceName: "Test & Europe #1"}
	text, err := HysteriaURI(c)
	if err != nil {
		t.Fatal("valid URI rejected")
	}
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "hysteria2" || u.Hostname() != c.Address || u.Port() != "8443" || u.User.Username() != c.UUID || u.Query().Get("sni") != c.ServerName || u.Query().Get("insecure") != "0" || u.Fragment != c.ServiceName {
		t.Fatal("URI round trip failed")
	}
	for _, bad := range []string{"", "host:443", "https://host", "host/path", "[::1]", "x@host", "host?query"} {
		c.Address = bad
		if value, err := HysteriaURI(c); err != ErrHysteriaConfig || value != "" {
			t.Fatal("invalid endpoint accepted")
		}
	}
}
