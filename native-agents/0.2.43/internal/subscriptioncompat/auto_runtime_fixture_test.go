package subscriptioncompat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Only an explicit test worker exports these entirely synthetic configurations.
// Runtime tests supply loopback listeners and deterministic DNS in a separate
// Linux network namespace; no real client credential or VPN node is involved.
func TestExportAutoRuntimeFixtures(t *testing.T) {
	root := os.Getenv("PAUK_AUTO_RUNTIME_FIXTURES_DIR")
	if root == "" {
		return
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute fixture destination required")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	h := Host{Name: "Авто", Address: "127.0.0.1", Port: 19080, Protocol: "vless", Transport: "tcp", Security: "tls", ProtocolOptions: Options{"encryption": "none"}, SecurityOptions: Options{"serverName": "vpn.fixture.test"}, Automatic: true, AutoRussiaDirect: true}
	for _, format := range []string{"XRAY_JSON", "SINGBOX", "MIHOMO"} {
		raw, err := RenderClient([]Host{h}, NativeTemplate(format), format, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
		if err != nil {
			t.Fatal(format, err)
		}
		if format == "XRAY_JSON" {
			var configs []Options
			if json.Unmarshal(raw, &configs) != nil || len(configs) != 1 {
				t.Fatal("xray fixture")
			}
			raw, err = json.Marshal(configs[0])
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, format+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAutoRoutingNamespaceAndDemandResolution(t *testing.T) {
	h := testHost("tcp")
	h.Name = "pauk-ru-direct"
	h.Automatic = true
	h.AutoRussiaDirect = true
	for _, format := range []string{"XRAY_JSON", "SINGBOX"} {
		template := NativeTemplate(format)
		if format == "XRAY_JSON" {
			template["outbounds"] = append(template["outbounds"].([]any), Options{"tag": "pauk-ru-direct", "protocol": "blackhole"})
		} else {
			template["outbounds"] = append(template["outbounds"].([]any), Options{"tag": "pauk-ru-direct", "type": "direct"})
		}
		raw, err := RenderClient([]Host{h}, template, format, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
		if err != nil {
			t.Fatal(err)
		}
		var cfg Options
		if format == "XRAY_JSON" {
			var rows []Options
			_ = json.Unmarshal(raw, &rows)
			cfg = rows[0]
			if object(cfg["routing"])["domainStrategy"] != "AsIs" {
				t.Fatal("compact website routing must preserve hostnames")
			}
		} else {
			_ = json.Unmarshal(raw, &cfg)
		}
		seen := map[string]bool{}
		for _, out := range cfg["outbounds"].([]any) {
			tag := text(object(out)["tag"])
			if seen[tag] {
				t.Fatal("duplicate outbound tag")
			}
			seen[tag] = true
		}
	}
}
