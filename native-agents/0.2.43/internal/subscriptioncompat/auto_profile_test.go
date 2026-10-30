package subscriptioncompat

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestAutoAssignmentRespectsFormatAndManualProfiles(t *testing.T) {
	hosts := []Host{testHost("xhttp"), testHost("tcp")}
	hosts[0].Name = "Manual XHTTP"
	hosts[1].Name = "Manual TCP"
	profile := AutoProfile{Enabled: true, Name: "🌍 Мой выбор", RussiaDirect: true, ClientKey: "synthetic-client", Candidates: []AutoCandidate{{0, "node-a", "service-a"}, {1, "node-b", "service-b"}}}
	before := append([]Host(nil), hosts...)
	for _, format := range []string{"XRAY_JSON", "XRAY_BASE64", "SINGBOX", "MIHOMO", "STASH"} {
		out, ok := WithAuto(hosts, profile, format)
		if !ok || len(out) != 3 || out[0].Name != profile.Name || !out[0].Automatic || !reflect.DeepEqual(out[1:], before) {
			t.Fatal("auto changed manual profiles")
		}
		if (format == "SINGBOX" || format == "STASH") && out[0].Transport == "xhttp" {
			t.Fatal("unsupported auto transport")
		}
	}
	profile.Candidates = nil
	if out, ok := WithAuto(hosts, profile, "XRAY_JSON"); ok || !reflect.DeepEqual(out, hosts) {
		t.Fatal("empty pool invented an endpoint")
	}
	profile.Enabled = false
	if _, ok := WithAuto(hosts, profile, "XRAY_JSON"); ok {
		t.Fatal("disabled setting ignored")
	}
	if !reflect.DeepEqual(hosts, before) {
		t.Fatal("source mutated")
	}
}

func TestAutoXrayRussiaDirectAndForeignFailClosed(t *testing.T) {
	h := testHost("tcp")
	h.Automatic = true
	h.AutoRussiaDirect = true
	h.Name = "Авто"
	manual := h
	manual.Automatic = false
	manual.AutoRussiaDirect = false
	manual.Name = "Manual"
	template := NativeTemplate("XRAY_JSON")
	template["routing"] = Options{"rules": []any{Options{"type": "field", "network": "tcp,udp", "outboundTag": "direct"}}}
	raw, err := RenderClient([]Host{h, manual}, template, "XRAY_JSON", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) >= 64*1024 {
		t.Fatal("mobile Auto configuration is too large")
	}
	var configs []Options
	if json.Unmarshal(raw, &configs) != nil || len(configs) != 2 {
		t.Fatal("profiles lost")
	}
	rules := object(configs[0]["routing"])["rules"].([]any)
	if object(rules[0])["outboundTag"] != "proxy" || object(rules[1])["outboundTag"] != "pauk-dns-out" || object(rules[len(rules)-1])["outboundTag"] != "proxy" {
		t.Fatal("DNS or foreign fallback escaped VPN")
	}
	if object(rules[2])["outboundTag"] != "pauk-ru-direct" || object(rules[3])["outboundTag"] != "proxy" {
		t.Fatal("compact Russia-direct or foreign fallback missing")
	}
	if _, hasIP := object(rules[2])["ip"]; hasIP {
		t.Fatal("mobile Auto profile must not embed the country CIDR list")
	}
	if object(configs[0]["routing"])["domainStrategy"] != "AsIs" {
		t.Fatal("website routing should use its hostname without demand resolution")
	}
	ordinary := object(configs[1]["routing"])["rules"].([]any)
	if len(ordinary) != 3 || object(ordinary[2])["outboundTag"] != "direct" {
		t.Fatal("manual routing changed")
	}
	for _, name := range []string{"ru", "xn--p1ai", "yandex.ru", "vk.com"} {
		found := false
		for _, suffix := range russiaRules.Suffix {
			if suffix == name {
				found = true
			}
		}
		if !found {
			t.Fatal("Russian domain absent")
		}
	}
	for _, name := range []string{"google.com", "wikipedia.org", "telegram.org", "t.me"} {
		for _, suffix := range russiaRules.Suffix {
			if name == suffix || strings.HasSuffix(name, "."+suffix) {
				t.Fatal("foreign domain incorrectly bypassed")
			}
		}
	}
	if len(russiaRules.CIDR) < 1000 || len(russiaRules.Regex) != 0 {
		t.Fatal("routing data unexpected")
	}
	for _, raw := range russiaRules.CIDR {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Bits() == 0 || prefix.Contains(netip.MustParseAddr("1.1.1.1")) || prefix.Contains(netip.MustParseAddr("8.8.8.8")) {
			t.Fatal("invalid geographic network")
		}
	}
	h.AutoRussiaDirect = false
	raw, err = RenderClient([]Host{h}, template, "XRAY_JSON", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if err != nil || bytes.Contains(raw, []byte("pauk-ru-direct")) {
		t.Fatal("Russia direct cannot be disabled")
	}
}

func TestAutoStructuredAndHonestURIHeaders(t *testing.T) {
	h := testHost("tcp")
	h.Automatic = true
	h.AutoRussiaDirect = true
	h.Name = "Авто"
	for _, format := range []string{"SINGBOX", "MIHOMO", "STASH"} {
		raw, err := RenderClient([]Host{h}, NativeTemplate(format), format, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
		if err != nil || !json.Valid(raw) {
			t.Fatalf("structured auto %s", format)
		}
		var cfg Options
		_ = json.Unmarshal(raw, &cfg)
		if format == "SINGBOX" {
			route := object(cfg["route"])
			if route["final"] != "PAUK" || len(route["rules"].([]any)) != 5 {
				t.Fatal("singbox routing")
			}
			if object(route["rules"].([]any)[3])["action"] != "resolve" {
				t.Fatal("domain-only destinations skip geographic IP matching")
			}
			if bytes.Contains(raw, []byte(`"geoip"`)) || bytes.Contains(raw, []byte(`"geosite"`)) {
				t.Fatal("removed singbox syntax")
			}
		} else {
			rules := cfg["rules"].([]any)
			if !strings.HasPrefix(text(rules[len(rules)-1]), "MATCH,") || bytes.Contains(raw, []byte(",DIRECT,no-resolve")) {
				t.Fatal("foreign default or geographic DNS missing")
			}
		}
	}
	profile := AutoProfile{Name: "Авто", RussiaDirect: true}
	for _, format := range []string{"XRAY_BASE64", "XRAY_JSON"} {
		headers := http.Header{}
		SetClientNetworkHeaders(headers, "Happ/3.0")
		SetAutoNetworkHeaders(headers, "Happ/3.0", format, profile)
		if format == "XRAY_BASE64" && headers.Get("X-PAUK-Russia-Direct") != "client-rules-required" {
			t.Fatal("URI-only routing misrepresented")
		}
		if format == "XRAY_JSON" && headers.Get("Routing") != "" {
			t.Fatal("global proxy preset conflicts with JSON")
		}
	}
}

func TestNativeShadowsocksPreservedWithoutImportingSecrets(t *testing.T) {
	password := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + ":" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	h := Host{Name: "SS", Address: "ss.example.test", Port: 8388, Protocol: "shadowsocks", Transport: "tcp,udp", Security: "shadowsocks", NativeShadowsocksPassword: password}
	for _, format := range []string{"XRAY_BASE64", "XRAY_JSON", "SINGBOX", "MIHOMO"} {
		raw, err := RenderClient([]Host{h}, NativeTemplate(format), format, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
		if err != nil {
			t.Fatal(format)
		}
		if format != "XRAY_BASE64" && !bytes.Contains(raw, []byte(password)) {
			t.Fatal("SS credential lost")
		}
	}
	raw, _ := json.Marshal(h)
	var imported Host
	_ = json.Unmarshal(raw, &imported)
	if validHost(imported) || bytes.Contains(raw, []byte(password)) {
		t.Fatal("private SS credential imported or serialized")
	}
}
