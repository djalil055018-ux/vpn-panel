package subscriptioncompat

import (
	"bytes"
	"encoding/json"
	"testing"
	"vpn-platform/internal/remnawave"
)

func policySourceFixture() (Options, Options) {
	p := policyFixture()
	raw, _ := json.Marshal(p)
	var policy Options
	_ = json.Unmarshal(raw, &policy)
	external := Options{"uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "hostOverrides": nil, "subscriptionSettings": nil, "templates": []any{}, "responseHeadersRemove": []any{"profile-title", "profile-web-page-url", "announce"}, "responseHeadersAdd": Options{"profile-title": "rwEncodeBase64:External"}, "hwidSettings": Options{"enabled": false, "fallbackDeviceLimit": 9999, "maxDevicesAnnounce": nil}, "subpageConfigUuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	inv := Options{"format": 1, "kind": "remnawave_inventory", "contract_version": "3.4.3", "contract_commit": remnawave.ContractCommit, "source_origin": "https://source.example.test", "started_at": "2026-01-01T00:00:00Z", "captured_at": "2026-01-01T00:00:00Z",
		"source_metadata": Options{"version": "3.4.3"}, "users": []any{}, "devices": []any{}, "internal_squads": Options{}, "external_squads": Options{"externalSquads": []any{external}}, "hosts": []any{}, "nodes": []any{}, "config_profiles": Options{},
		"verification": Options{"source_total": 0, "unique_user_ids": 0, "stable_user_passes": 2, "stable_access_configuration_passes": 2, "atomic_database_snapshot": true}}
	s := Options{"uuid": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "custom_remarks": policy["remarks"], "custom_response_headers": policy["headers"], "hwid_settings": policy["hwid"], "is_show_custom_remarks": true, "randomize_hosts": false, "response_rules": policy["rules"], "serve_json_at_base_subscription": true}
	settings := Options{"format": 1, "kind": "remnawave_subscription_settings_snapshot", "source_origin": "https://source.example.test", "captured_at": "2026-01-01T00:00:00Z",
		"tables": Options{"subscription_settings": []any{s}, "subscription_page_config": []any{Options{"uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "name": "Default", "view_position": 1, "config": Options{"version": "synthetic"}}}, "subscription_templates": []any{}}}
	return inv, settings
}
func policyGlobal(s Options) Options {
	return object(object(s["tables"])["subscription_settings"].([]any)[0])
}
func policyExternal(i Options) Options {
	return object(object(i["external_squads"])["externalSquads"].([]any)[0])
}
func TestSubscriptionPolicySourceProjection(t *testing.T) {
	i, s := policySourceFixture()
	iraw, _ := json.Marshal(i)
	sraw, _ := json.Marshal(s)
	p, err := ProjectPolicies(iraw, sraw)
	if err != nil || len(p.External) != 1 || len(p.Pages) != 1 || len(p.UserExternal) != 0 || len(p.SettingsSHA256) != 64 || len(p.InventorySHA256) != 64 {
		t.Fatal("source policy projection")
	}
	e := p.External["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
	if e.Headers["profile-title"] != "rwEncodeBase64:External" || e.Headers["profile-web-page-url"] != "" || p.Global.Headers["profile-web-page-url"] == "" || *e.HWID.Fallback != 9999 || *p.Global.HWID.Fallback != 2 {
		t.Fatal("external override mismatch")
	}
	if p.Global.PageID == nil || e.PageID == nil || *p.Global.PageID != *e.PageID {
		t.Fatal("page identity")
	}
}
func TestSubscriptionPolicySourceRejections(t *testing.T) {
	cases := map[string]func(Options, Options){
		"origin":          func(i, s Options) { s["source_origin"] = "https://different.example.test" },
		"kind":            func(i, s Options) { s["kind"] = "other" },
		"randomized":      func(i, s Options) { policyGlobal(s)["randomize_hosts"] = true },
		"missing-control": func(i, s Options) { delete(policyGlobal(s), "serve_json_at_base_subscription") },
		"unknown-control": func(i, s Options) { policyGlobal(s)["new_control"] = true },
		"rules-control":   func(i, s Options) { object(policyGlobal(s)["response_rules"])["future_behavior"] = true },
		"condition-control": func(i, s Options) {
			object(object(policyGlobal(s)["response_rules"])["rules"].([]any)[0])["future_behavior"] = true
		},
		"HWID-control": func(i, s Options) { object(policyGlobal(s)["hwid_settings"])["new_enforcement"] = true },
		"unknown-page": func(i, s Options) { policyExternal(i)["subpageConfigUuid"] = "dddddddd-dddd-4ddd-8ddd-dddddddddddd" },
		"ambiguous-page": func(i, s Options) {
			tables := object(s["tables"])
			tables["subscription_page_config"] = append(tables["subscription_page_config"].([]any), tables["subscription_page_config"].([]any)[0])
		},
		"duplicate-external": func(i, s Options) {
			object(i["external_squads"])["externalSquads"] = append(object(i["external_squads"])["externalSquads"].([]any), policyExternal(i))
		},
		"host-override": func(i, s Options) { policyExternal(i)["hostOverrides"] = Options{"address": "elsewhere.example.test"} },
		"settings-override": func(i, s Options) {
			policyExternal(i)["subscriptionSettings"] = Options{"serveJsonAtBaseSubscription": false}
		},
		"external-template":     func(i, s Options) { policyExternal(i)["templates"] = []any{Options{"templateType": "XRAY_JSON"}} },
		"external-HWID":         func(i, s Options) { object(policyExternal(i)["hwidSettings"])["enabled"] = true },
		"external-HWID-control": func(i, s Options) { object(policyExternal(i)["hwidSettings"])["new_enforcement"] = true },
		"external-header":       func(i, s Options) { policyExternal(i)["responseHeadersAdd"] = Options{"set-cookie": "x=1"} },
		"unexpected-table":      func(i, s Options) { object(s["tables"])["external_squads_templates"] = []any{Options{"x": true}} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			i, s := policySourceFixture()
			mutate(i, s)
			iraw, _ := json.Marshal(i)
			sraw, _ := json.Marshal(s)
			if _, err := ProjectPolicies(iraw, sraw); err != ErrProfile {
				t.Fatal("unsupported source policy accepted")
			}
		})
	}
	i, s := policySourceFixture()
	iraw, _ := json.Marshal(i)
	sraw, _ := json.Marshal(s)
	sraw = bytes.Replace(sraw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1)
	if _, err := ProjectPolicies(iraw, sraw); err != ErrProfile {
		t.Fatal("duplicate source JSON")
	}
}
