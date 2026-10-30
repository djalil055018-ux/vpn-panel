package xrayprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
)

const sourceNodeID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const sourceProfileID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

func sourceFixture(t *testing.T) (map[string]any, []SourceServiceAssignment) {
	t.Helper()
	raw, _, services := fixture(t)
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("fixture decode")
	}
	metadata := []any{}
	assignments := []SourceServiceAssignment{}
	for i, v := range cfg["inbounds"].([]any) {
		in := v.(map[string]any)
		stream := in["streamSettings"].(map[string]any)
		id := fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012d", i+1)
		metadata = append(metadata, map[string]any{"uuid": id, "profileUuid": sourceProfileID, "tag": in["tag"], "type": in["protocol"], "network": stream["network"], "security": stream["security"], "port": in["port"], "rawInbound": in})
		a := SourceServiceAssignment{InboundID: id, ServiceID: services[i].ID}
		if services[i].TLS != nil {
			a.TLS = &model.TLSSpec{CertificateID: services[i].TLS.CertificateID, ServerName: services[i].TLS.ServerName}
		}
		assignments = append(assignments, a)
	}
	inv := map[string]any{"format": 1, "kind": "remnawave_inventory", "contract_version": "3.4.3", "contract_commit": remnawave.ContractCommit,
		"source_origin": "https://source.example.test", "started_at": "2026-01-01T00:00:00Z", "captured_at": "2026-01-01T00:00:00Z",
		"source_metadata": map[string]any{"version": "3.4.3"}, "users": []any{}, "devices": []any{}, "internal_squads": map[string]any{}, "external_squads": map[string]any{}, "hosts": []any{},
		"nodes": []any{map[string]any{"uuid": sourceNodeID, "isDisabled": false, "activePluginUuid": nil, "proxyUrl": nil, "consumptionMultiplier": 1, "nodeConsumptionMultiplier": 1,
			"configProfile": map[string]any{"activeConfigProfileUuid": sourceProfileID, "activeInbounds": metadata[:3]}}},
		"config_profiles": map[string]any{"configProfiles": []any{map[string]any{"uuid": sourceProfileID, "config": cfg, "inbounds": metadata, "nodes": []any{map[string]any{"uuid": sourceNodeID}}}}},
		"verification":    map[string]any{"source_total": 0, "unique_user_ids": 0, "stable_user_passes": 2, "stable_access_configuration_passes": 2, "atomic_database_snapshot": true}}
	// Remove all aliases between node metadata, profile metadata and raw config.
	wire, _ := json.Marshal(inv)
	if json.Unmarshal(wire, &inv) != nil {
		t.Fatal("fixture copy")
	}
	return inv, assignments
}
func sourceFixtureNode(inv map[string]any) map[string]any {
	return inv["nodes"].([]any)[0].(map[string]any)
}
func sourceFixtureProfile(inv map[string]any) map[string]any {
	return inv["config_profiles"].(map[string]any)["configProfiles"].([]any)[0].(map[string]any)
}

func TestXrayProfileSourceProjection(t *testing.T) {
	inv, assignments := sourceFixture(t)
	raw, _ := json.Marshal(inv)
	before := append([]byte(nil), raw...)
	out, err := ProjectSourceNode(raw, sourceNodeID, assignments)
	if err != nil || out.NodeID != sourceNodeID || out.ProfileID != sourceProfileID || len(out.Services) != 4 {
		t.Fatal("projection")
	}
	req, err := SourceNodeRequirements(raw, sourceNodeID)
	if err != nil || len(req) != 4 {
		t.Fatal("requirements")
	}
	for i, s := range out.Services {
		if s.Enabled != (i < 3) || s.Service.ID != assignments[i].ServiceID || s.InboundID != assignments[i].InboundID || len(s.Service.Clients) != 0 ||
			req[i].ID != s.InboundID || req[i].Tag != s.InboundTag || req[i].Enabled != s.Enabled || req[i].Security != s.Service.Security {
			t.Fatal("source identity or enabled state lost")
		}
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("source changed")
	}
	wire, _ := json.Marshal(out)
	_, _, withSecrets := fixture(t)
	for _, secret := range []string{withSecrets[0].Reality.PrivateKey, "/source/private", "/runtime", "22222222-2222-4222-8222-222222222222"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatal("private material leaked")
		}
	}
	assignments[0], assignments[3] = assignments[3], assignments[0]
	again, err := ProjectSourceNode(raw, sourceNodeID, assignments)
	if err != nil || !reflect.DeepEqual(out, again) {
		t.Fatal("assignment order changed projection")
	}
}

func TestXrayProfileSourceCrossReferences(t *testing.T) {
	cases := map[string]func(map[string]any){
		"duplicate-node": func(v map[string]any) { v["nodes"] = append(v["nodes"].([]any), sourceFixtureNode(v)) },
		"duplicate-profile": func(v map[string]any) {
			p := v["config_profiles"].(map[string]any)
			p["configProfiles"] = append(p["configProfiles"].([]any), sourceFixtureProfile(v))
		},
		"disabled":         func(v map[string]any) { sourceFixtureNode(v)["isDisabled"] = true },
		"missing-disabled": func(v map[string]any) { delete(sourceFixtureNode(v), "isDisabled") },
		"plugin":           func(v map[string]any) { sourceFixtureNode(v)["activePluginUuid"] = sourceProfileID },
		"missing-plugin":   func(v map[string]any) { delete(sourceFixtureNode(v), "activePluginUuid") },
		"proxy":            func(v map[string]any) { sourceFixtureNode(v)["proxyUrl"] = "https://proxy.example.test" },
		"missing-proxy":    func(v map[string]any) { delete(sourceFixtureNode(v), "proxyUrl") },
		"multiplier":       func(v map[string]any) { sourceFixtureNode(v)["consumptionMultiplier"] = 2 },
		"node-multiplier":  func(v map[string]any) { sourceFixtureNode(v)["nodeConsumptionMultiplier"] = 2 },
		"wrong-profile": func(v map[string]any) {
			sourceFixtureNode(v)["configProfile"].(map[string]any)["activeConfigProfileUuid"] = sourceNodeID
		},
		"missing-backlink": func(v map[string]any) { sourceFixtureProfile(v)["nodes"] = []any{} },
		"duplicate-backlink": func(v map[string]any) {
			p := sourceFixtureProfile(v)
			p["nodes"] = append(p["nodes"].([]any), p["nodes"].([]any)[0])
		},
		"missing-metadata": func(v map[string]any) { p := sourceFixtureProfile(v); p["inbounds"] = p["inbounds"].([]any)[:3] },
		"duplicate-metadata": func(v map[string]any) {
			p := sourceFixtureProfile(v)
			p["inbounds"].([]any)[1] = p["inbounds"].([]any)[0]
		},
		"metadata-tag": func(v map[string]any) {
			sourceFixtureProfile(v)["inbounds"].([]any)[0].(map[string]any)["tag"] = "other"
		},
		"metadata-profile": func(v map[string]any) {
			sourceFixtureProfile(v)["inbounds"].([]any)[0].(map[string]any)["profileUuid"] = sourceNodeID
		},
		"metadata-network": func(v map[string]any) {
			sourceFixtureProfile(v)["inbounds"].([]any)[0].(map[string]any)["network"] = "grpc"
		},
		"metadata-port": func(v map[string]any) {
			sourceFixtureProfile(v)["inbounds"].([]any)[0].(map[string]any)["port"] = 12345
		},
		"metadata-raw": func(v map[string]any) {
			sourceFixtureProfile(v)["inbounds"].([]any)[0].(map[string]any)["rawInbound"].(map[string]any)["port"] = 12345
		},
		"active-wrong-id": func(v map[string]any) {
			sourceFixtureNode(v)["configProfile"].(map[string]any)["activeInbounds"].([]any)[0].(map[string]any)["uuid"] = sourceProfileID
		},
		"active-raw": func(v map[string]any) {
			sourceFixtureNode(v)["configProfile"].(map[string]any)["activeInbounds"].([]any)[0].(map[string]any)["rawInbound"].(map[string]any)["port"] = 12345
		},
		"active-duplicate": func(v map[string]any) {
			c := sourceFixtureNode(v)["configProfile"].(map[string]any)
			c["activeInbounds"].([]any)[1] = c["activeInbounds"].([]any)[0]
		},
		"active-null": func(v map[string]any) { sourceFixtureNode(v)["configProfile"].(map[string]any)["activeInbounds"] = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			inv, a := sourceFixture(t)
			change(inv)
			raw, _ := json.Marshal(inv)
			if _, err := ProjectSourceNode(raw, sourceNodeID, a); err != ErrProfile {
				t.Fatal("ambiguous source accepted")
			}
			if _, err := SourceNodeRequirements(raw, sourceNodeID); err != ErrProfile {
				t.Fatal("requirements bypassed source validation")
			}
		})
	}
	for _, name := range []string{"missing", "duplicate", "unknown", "reused-native-id", "unexpected-tls", "missing-tls", "private-path"} {
		t.Run(name, func(t *testing.T) {
			inv, a := sourceFixture(t)
			raw, _ := json.Marshal(inv)
			switch name {
			case "missing":
				a = a[:3]
			case "duplicate":
				a[1] = a[0]
			case "unknown":
				a[0].InboundID = sourceProfileID
			case "reused-native-id":
				a[1].ServiceID = a[0].ServiceID
			case "unexpected-tls":
				a[0].TLS = a[3].TLS
			case "missing-tls":
				a[3].TLS = nil
			case "private-path":
				a[3].TLS.KeyFile = "/private/key.pem"
			}
			if _, err := ProjectSourceNode(raw, sourceNodeID, a); err != ErrProfile {
				t.Fatal("invalid assignment accepted")
			}
		})
	}
}
