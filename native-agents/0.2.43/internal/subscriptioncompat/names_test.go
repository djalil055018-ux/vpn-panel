package subscriptioncompat

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestPublicNamesAvoidStructuredConfigCollisions(t *testing.T) {
	credential := strings.Repeat("a", 8) + "-aaaa-4aaa-8aaa-" + strings.Repeat("a", 12)
	for _, format := range []string{"MIHOMO", "STASH", "CLASH", "SINGBOX"} {
		t.Run(format, func(t *testing.T) {
			direct := "DIRECT"
			template := Options{"proxy-groups": []any{Options{"name": "Main", "type": "select", "proxies": []any{"DIRECT"}}}}
			if format == "SINGBOX" {
				direct = "direct"
				template = Options{"outbounds": []any{Options{"type": "direct", "tag": direct}, Options{"type": "selector", "tag": "Main"}}}
			}
			names := []string{"🇳🇱 Нидерланды", "🇳🇱 Нидерланды", "🇳🇱 Нидерланды · 2", "Main", direct}
			hosts := []Host{}
			for _, name := range names {
				hosts = append(hosts, Host{Name: name, Address: "example.test", Port: 443, Protocol: "trojan", Transport: "tcp", Security: "tls", SecurityOptions: Options{"serverName": "example.test"}})
			}
			before, _ := json.Marshal([]any{hosts, template})
			raw, err := Render(hosts, template, format, credential)
			if err != nil {
				t.Fatal(err)
			}
			var cfg Options
			if json.Unmarshal(raw, &cfg) != nil {
				t.Fatal("invalid configuration")
			}
			got := []string{}
			refs := []any{}
			if format == "SINGBOX" {
				rows := cfg["outbounds"].([]any)
				for _, row := range rows[2:] {
					got = append(got, text(object(row)["tag"]))
				}
				if object(rows[0])["tag"] != direct || object(rows[1])["tag"] != "Main" {
					t.Fatal("template tags changed")
				}
				refs = object(rows[1])["outbounds"].([]any)
			} else {
				for _, row := range cfg["proxies"].([]any) {
					got = append(got, text(object(row)["name"]))
				}
				group := object(cfg["proxy-groups"].([]any)[0])
				if group["name"] != "Main" {
					t.Fatal("template group changed")
				}
				all := group["proxies"].([]any)
				if all[0] != direct {
					t.Fatal("builtin reference changed")
				}
				refs = all[1:]
			}
			want := []string{names[0], names[0] + " · 3", names[2], "Main · 2", direct + " · 2"}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("duplicate or reserved profile name not disambiguated")
			}
			if len(refs) != len(got) {
				t.Fatal("profiles lost from selector")
			}
			for i := range got {
				if refs[i] != got[i] {
					t.Fatal("selector references old name")
				}
			}
			after, _ := json.Marshal([]any{hosts, template})
			if !bytes.Equal(before, after) {
				t.Fatal("saved names or template mutated")
			}
			repeated, err := Render(hosts, template, format, credential)
			if err != nil || !bytes.Equal(raw, repeated) {
				t.Fatal("names are not stable")
			}
		})
	}
}

func TestPublicNamesKeepExactIndependentProfileLabels(t *testing.T) {
	credential := strings.Repeat("a", 8) + "-aaaa-4aaa-8aaa-" + strings.Repeat("a", 12)
	h := testHost("tcp")
	h.Name = "🇳🇱 Нидерланды & #1"
	for _, format := range []string{"XRAY_BASE64", "XRAY_JSON"} {
		raw, err := Render([]Host{h, h}, Options{}, format, credential)
		if err != nil {
			t.Fatal(err)
		}
		if format == "XRAY_BASE64" {
			decoded, err := base64.StdEncoding.DecodeString(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(decoded), "\n")
			if len(lines) != 2 {
				t.Fatal("profile lost")
			}
			for _, line := range lines {
				u, err := url.Parse(line)
				if err != nil || u.Fragment != h.Name {
					t.Fatal("exact URI label changed")
				}
			}
		} else {
			var rows []Options
			if json.Unmarshal(raw, &rows) != nil || len(rows) != 2 {
				t.Fatal("profile lost")
			}
			for _, row := range rows {
				if row["remarks"] != h.Name {
					t.Fatal("exact Xray label changed")
				}
			}
		}
	}
}

func TestPublicNamesIgnoreExcludedHostsWhenAllocatingLabels(t *testing.T) {
	credential := strings.Repeat("a", 8) + "-aaaa-4aaa-8aaa-" + strings.Repeat("a", 12)
	h := testHost("tcp")
	h.Name = "🇳🇱 Нидерланды"
	disabled := h
	disabled.Name += " · 2"
	disabled.Metadata.Disabled = true
	for _, format := range []string{"SINGBOX", "MIHOMO", "STASH"} {
		raw, err := Render([]Host{h, disabled, h}, Options{}, format, credential)
		if err != nil {
			t.Fatal(err)
		}
		var cfg Options
		if json.Unmarshal(raw, &cfg) != nil {
			t.Fatal("invalid configuration")
		}
		key, field := "proxies", "name"
		if format == "SINGBOX" {
			key, field = "outbounds", "tag"
		}
		rows := cfg[key].([]any)
		if len(rows) != 2 || object(rows[0])[field] != h.Name || object(rows[1])[field] != h.Name+" · 2" {
			t.Fatal("excluded host consumed visible name")
		}
	}
}
