package subscriptioncompat

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSubscriptionYAMLMergeAndTypes(t *testing.T) {
	raw := []byte("base: &base\n  type: select\n  enabled: false\n  port: 443\n  proxies: null\nproxy-groups:\n  - <<: *base\n    name: Group\n    port: 8443\n  - <<: [*base]\n    name: Other\nvalues: [yes, true, off, false, null, 1.5]\n")
	out, err := parseTemplateYAML(raw)
	if err != nil {
		t.Fatal("bounded YAML merge")
	}
	groups := out["proxy-groups"].([]any)
	if !reflect.DeepEqual(groups[0], Options{"type": "select", "enabled": false, "port": float64(8443), "proxies": nil, "name": "Group"}) {
		t.Fatal("merge precedence")
	}
	if !reflect.DeepEqual(out["values"], []any{"yes", true, "off", false, nil, float64(1.5)}) {
		t.Fatal("YAML scalar semantics")
	}
}
func TestSubscriptionYAMLRejectAmbiguity(t *testing.T) {
	for name, raw := range map[string]string{
		"duplicate":   "port: 1\nport: 2\n",
		"multiple":    "port: 1\n---\nport: 2\n",
		"cycle":       "base: &loop [*loop]\n",
		"custom-tag":  "value: !secret payload\n",
		"numeric-key": "1: value\n",
		"octal":       "value: 0777\n",
		"hex":         "value: 0x10\n",
		"infinity":    "value: .inf\n",
		"nan":         "value: .nan\n",
		"timestamp":   "value: 2026-01-01\n",
		"array-root":  "[one,two]\n",
		"depth":       "value: " + strings.Repeat("[", 50) + "0" + strings.Repeat("]", 50),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTemplateYAML([]byte(raw)); err != ErrProfile {
				t.Fatal("ambiguous YAML accepted")
			}
		})
	}
}
func templateSettingsFixture() Options {
	_, s := policySourceFixture()
	rows := []any{}
	for i, format := range []string{"XRAY_JSON", "SINGBOX", "MIHOMO", "STASH", "CLASH"} {
		row := Options{"uuid": fmt.Sprintf("dddddddd-dddd-4ddd-8ddd-%012d", i+1), "name": "Default", "template_type": format, "template_json": nil, "template_yaml": nil}
		switch format {
		case "XRAY_JSON":
			row["template_json"] = Options{"outbounds": []any{Options{"protocol": "freedom", "tag": "direct"}}}
		case "SINGBOX":
			row["template_json"] = Options{"outbounds": []any{Options{"type": "direct", "tag": "direct"}, Options{"type": "selector", "tag": "Select", "outbounds": nil}}}
		default:
			row["template_yaml"] = "proxies: null\nproxy-groups:\n  - name: Select\n    type: select\n    proxies: null\n"
		}
		rows = append(rows, row)
	}
	object(s["tables"])["subscription_templates"] = rows
	return s
}
func TestSubscriptionSourceTemplates(t *testing.T) {
	s := templateSettingsFixture()
	wire, _ := json.Marshal(s)
	templates, err := ProjectTemplates(wire)
	if err != nil || len(templates) != 5 {
		t.Fatal("source template projection")
	}
	for format, v := range templates {
		if v.Format != format || len(v.SourceSHA256) != 64 || v.Body == nil {
			t.Fatal("template provenance")
		}
	}
	cases := map[string]func([]any){
		"missing":          func(rows []any) { object(rows[0])["template_json"] = nil },
		"custom-name":      func(rows []any) { object(rows[0])["name"] = "other" },
		"duplicate-id":     func(rows []any) { object(rows[1])["uuid"] = object(rows[0])["uuid"] },
		"duplicate-format": func(rows []any) { object(rows[1])["template_type"] = "XRAY_JSON" },
		"dual-source":      func(rows []any) { object(rows[2])["template_json"] = Options{} },
		"unparsed-control": func(rows []any) { object(rows[0])["future_renderer"] = true },
		"malformed-yaml":   func(rows []any) { object(rows[2])["template_yaml"] = "key: one\nkey: two" },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			s := templateSettingsFixture()
			modify(object(s["tables"])["subscription_templates"].([]any))
			wire, _ := json.Marshal(s)
			if _, err := ProjectTemplates(wire); err != ErrProfile {
				t.Fatal("unsupported template accepted")
			}
		})
	}
}
