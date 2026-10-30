package compiler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

const cascadeServiceID = "11111111-1111-4111-8111-111111111111"
const cascadeID = "22222222-2222-4222-8222-222222222222"
const cascadeClientID = "33333333-3333-4333-8333-333333333333"
const cascadeStatsID = "44444444-4444-4444-8444-444444444444"
const cascadeTransitID = "55555555-5555-4555-8555-555555555555"

func cascadeFixture() model.DesiredState {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	s := model.ServiceSpec{ID: cascadeServiceID, Protocol: "vless", Listen: "0.0.0.0", Port: 443, Transport: "tcp", Security: "reality", Reality: &model.RealitySpec{Destination: "example.org:443", ServerName: "example.org", ShortID: "abcd", PrivateKey: key, SecretRef: "reality/" + cascadeServiceID}, Clients: []model.ClientSpec{{ID: cascadeClientID, StatsKey: cascadeStatsID}}}
	return model.DesiredState{Generation: 3, Core: model.CoreRelease{Type: "xray", Version: xrayprofile.MinimumCore}, Services: []model.ServiceSpec{s}, XrayCascades: &model.XrayCascadesSpec{Version: 1, Entries: []model.XrayCascadeEntry{{ID: cascadeID, ServiceID: cascadeServiceID, Port: 8443, Clients: append([]model.ClientSpec{}, s.Clients...), Exit: model.XrayCascadeEndpoint{Address: "exit.example.org", Port: 443, ClientID: cascadeTransitID, ServerName: "example.org", PublicKey: key, ShortID: "abcd", Fingerprint: "firefox"}}}}}
}

func cascadeDocument(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		t.Fatal("invalid compiled document")
	}
	return doc
}

func TestCascadeEntryPreservesOrdinaryProfileAndHasNoDirectFallback(t *testing.T) {
	state := cascadeFixture()
	before, _ := json.Marshal(state)
	base, err := compileXrayBase(state)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CompileXray(state)
	if err != nil {
		t.Fatal(err)
	}
	a, b := cascadeDocument(t, base), cascadeDocument(t, raw)
	if !reflect.DeepEqual(a["inbounds"].([]any)[0], b["inbounds"].([]any)[0]) || !reflect.DeepEqual(a["outbounds"], b["outbounds"].([]any)[:2]) {
		t.Fatal("ordinary connection changed")
	}
	listener := b["inbounds"].([]any)[1].(map[string]any)
	if listener["port"] != float64(8443) || listener["tag"] != XrayCascadeInboundTag(cascadeID) {
		t.Fatal("dedicated listener missing")
	}
	original := a["inbounds"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(original["streamSettings"], listener["streamSettings"]) || !reflect.DeepEqual(original["settings"], listener["settings"]) {
		t.Fatal("entry identity or accounting changed")
	}
	rules := b["routing"].(map[string]any)["rules"].([]any)
	if !reflect.DeepEqual(rules[0], a["routing"].(map[string]any)["rules"].([]any)[0]) {
		t.Fatal("management API guard displaced")
	}
	route := rules[1].(map[string]any)
	if len(route) != 3 || route["outboundTag"] != XrayCascadeOutboundTag(cascadeID) || !reflect.DeepEqual(route["inboundTag"], []any{XrayCascadeInboundTag(cascadeID)}) {
		t.Fatal("cascade routing can fall through")
	}
	outbound := b["outbounds"].([]any)[2].(map[string]any)
	if outbound["protocol"] != "vless" || outbound["tag"] != route["outboundTag"] || outbound["proxySettings"] != nil {
		t.Fatal("unexpected cascade outbound")
	}
	after, _ := json.Marshal(state)
	if !bytes.Equal(before, after) {
		t.Fatal("compiler mutated desired state")
	}
}

func TestCascadeExitAddsOnlyDedicatedUncountedTransit(t *testing.T) {
	state := cascadeFixture()
	state.XrayCascades.Entries = nil
	state.XrayCascades.Exits = []model.XrayCascadeExit{{ID: cascadeID, ServiceID: cascadeServiceID, ClientID: cascadeTransitID}}
	raw, err := CompileXray(state)
	if err != nil {
		t.Fatal(err)
	}
	doc := cascadeDocument(t, raw)
	ins := doc["inbounds"].([]any)
	if len(ins) != 1 || len(doc["outbounds"].([]any)) != 2 {
		t.Fatal("exit created unrelated listeners or outbounds")
	}
	clients := ins[0].(map[string]any)["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 2 || clients[0].(map[string]any)["id"] != cascadeClientID {
		t.Fatal("ordinary authorization changed")
	}
	if !reflect.DeepEqual(clients[1], map[string]any{"id": cascadeTransitID}) {
		t.Fatal("transit credentials or double-counted user stats")
	}
}

func importedCascadeFixture(t *testing.T, explicit string) model.DesiredState {
	t.Helper()
	state := cascadeFixture()
	key := state.Services[0].Reality.PrivateKey
	settings := map[string]any{"decryption": "none", "clients": []any{}}
	if explicit != "default" {
		settings["flow"] = explicit
	}
	doc := map[string]any{"inbounds": []any{map[string]any{"tag": "imported-reality", "listen": "0.0.0.0", "port": 443, "protocol": "vless", "settings": settings, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"dest": "example.org:443", "serverNames": []string{"example.org"}, "shortIds": []string{"abcd"}, "privateKey": key}}}}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "DIRECT"}}}}
	raw, _ := json.Marshal(doc)
	profile, _, err := xrayprofile.Project(raw, []model.XrayProfileBinding{{ServiceID: cascadeServiceID, InboundTag: "imported-reality"}})
	if err != nil {
		t.Fatal(err)
	}
	state.XrayProfile = profile
	state.Services[0].Clients = nil
	return state
}

func TestCascadeImportedEmptyServiceDerivesFlowFromReviewedTemplate(t *testing.T) {
	for _, mode := range []string{"default", "none", "xtls-rprx-vision"} {
		t.Run(mode, func(t *testing.T) {
			state := importedCascadeFixture(t, mode)
			raw, err := CompileXray(state)
			if err != nil {
				t.Fatal(err)
			}
			doc := cascadeDocument(t, raw)
			in := doc["inbounds"].([]any)[1].(map[string]any)
			client := in["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
			if mode == "none" {
				if client["flow"] != nil {
					t.Fatal("explicit no-flow ignored")
				}
			} else if client["flow"] != "xtls-rprx-vision" {
				t.Fatal("template flow was inferred from absent ordinary users")
			}
			rules := doc["routing"].(map[string]any)["rules"].([]any)
			if len(rules) != 3 || rules[1].(map[string]any)["outboundTag"] != XrayCascadeOutboundTag(cascadeID) || rules[2].(map[string]any)["outboundTag"] != "DIRECT" {
				t.Fatal("original catch-all can bypass cascade")
			}
		})
	}
}

func TestCascadeMalformedPlanIsRejected(t *testing.T) {
	cases := map[string]func(*model.DesiredState){
		"version":             func(s *model.DesiredState) { s.XrayCascades.Version = 2 },
		"empty":               func(s *model.DesiredState) { s.XrayCascades.Entries = nil },
		"occupied port":       func(s *model.DesiredState) { s.XrayCascades.Entries[0].Port = 443 },
		"management port":     func(s *model.DesiredState) { s.XrayCascades.Entries[0].Port = 10085 },
		"missing service":     func(s *model.DesiredState) { s.XrayCascades.Entries[0].ServiceID = cascadeID },
		"other protocol":      func(s *model.DesiredState) { s.Services[0].Protocol = "trojan" },
		"endpoint URL":        func(s *model.DesiredState) { s.XrayCascades.Entries[0].Exit.Address = "https://exit.example.org" },
		"endpoint management": func(s *model.DesiredState) { s.XrayCascades.Entries[0].Exit.Port = 10085 },
		"bad key":             func(s *model.DesiredState) { s.XrayCascades.Entries[0].Exit.PublicKey = "invalid" },
		"odd short ID":        func(s *model.DesiredState) { s.XrayCascades.Entries[0].Exit.ShortID = "abc" },
		"bad flow":            func(s *model.DesiredState) { s.XrayCascades.Entries[0].Exit.Flow = "direct" },
		"missing statistics":  func(s *model.DesiredState) { s.XrayCascades.Entries[0].Clients[0].StatsKey = "" },
		"duplicate client": func(s *model.DesiredState) {
			s.XrayCascades.Entries[0].Clients = append(s.XrayCascades.Entries[0].Clients, s.XrayCascades.Entries[0].Clients[0])
		},
		"duplicate cascade": func(s *model.DesiredState) {
			s.XrayCascades.Entries = append(s.XrayCascades.Entries, s.XrayCascades.Entries[0])
		},
		"transit reuses ordinary credential": func(s *model.DesiredState) {
			s.XrayCascades.Entries = nil
			s.XrayCascades.Exits = []model.XrayCascadeExit{{ID: cascadeID, ServiceID: cascadeServiceID, ClientID: cascadeClientID}}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := cascadeFixture()
			change(&s)
			if _, err := CompileXray(s); err == nil {
				t.Fatal("unsafe cascade accepted")
			}
		})
	}
}

func TestCascadeAbsentPreservesCompiledBytes(t *testing.T) {
	state := cascadeFixture()
	state.XrayCascades = nil
	base, err := compileXrayBase(state)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CompileXray(state)
	if err != nil || !bytes.Equal(base, raw) {
		t.Fatal("ordinary runtime changed without a cascade")
	}
}
