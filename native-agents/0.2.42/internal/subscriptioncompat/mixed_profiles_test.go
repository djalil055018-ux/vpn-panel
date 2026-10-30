package subscriptioncompat

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestNativeTrojanAndWebSocketInMixedSubscription(t *testing.T) {
	credential := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	trojan := Host{Name: "Trojan", Address: "trojan.example.test", Port: 8443, Protocol: "trojan", Transport: "tcp", Security: "tls", SecurityOptions: Options{"serverName": "trojan.example.test", "fingerprint": "chrome"}}
	ws := Host{Name: "WebSocket", Address: "ws.example.test", Port: 4443, Protocol: "vless", Transport: "ws", Security: "tls", ProtocolOptions: Options{"encryption": "none"}, TransportOptions: Options{"path": "/vless/synthetic", "host": "ws.example.test"}, SecurityOptions: Options{"serverName": "ws.example.test", "fingerprint": "chrome"}}
	hosts := []Host{testHost("tcp"), trojan, ws}
	for _, format := range []string{"XRAY_BASE64", "XRAY_JSON", "SINGBOX", "MIHOMO", "STASH", "CLASH"} {
		t.Run(format, func(t *testing.T) {
			raw, err := Render(hosts, Options{}, format, credential)
			if err != nil {
				t.Fatal(err)
			}
			if format == "XRAY_BASE64" {
				decoded, err := base64.StdEncoding.DecodeString(string(raw))
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(string(decoded), "\n")
				if len(lines) != 3 {
					t.Fatal("missing mixed URI")
				}
				tr, _ := url.Parse(lines[1])
				web, _ := url.Parse(lines[2])
				if tr.Scheme != "trojan" || tr.User.Username() != credential || tr.Query().Get("encryption") != "" || web.Query().Get("path") != "/vless/synthetic" || web.Query().Get("host") != "ws.example.test" {
					t.Fatal("incorrect protocol or transport")
				}
			} else if format == "XRAY_JSON" {
				var configs []Options
				if json.Unmarshal(raw, &configs) != nil || len(configs) != 3 {
					t.Fatal("missing mixed Xray profile")
				}
				tr := object(configs[1]["outbounds"].([]any)[0])
				server := object(object(tr["settings"])["servers"].([]any)[0])
				if tr["protocol"] != "trojan" || server["password"] != credential {
					t.Fatal("Trojan lost its password")
				}
				web := object(configs[2]["outbounds"].([]any)[0])
				if object(object(web["streamSettings"])["wsSettings"])["path"] != "/vless/synthetic" {
					t.Fatal("WebSocket lost its path")
				}
			} else {
				var config Options
				if json.Unmarshal(raw, &config) != nil {
					t.Fatal("invalid client document")
				}
				key := "proxies"
				if format == "SINGBOX" {
					key = "outbounds"
				}
				entries := config[key].([]any)
				want := 3
				if format == "CLASH" {
					want = 1
				}
				if len(entries) != want {
					t.Fatal("missing supported client profiles")
				}
				found := false
				for _, entry := range entries {
					v := object(entry)
					if v["type"] == "trojan" {
						found = true
						if v["password"] != credential || v["uuid"] != nil {
							t.Fatal("wrong Trojan authentication")
						}
					}
				}
				if !found {
					t.Fatal("Trojan missing")
				}
			}
		})
	}
}
