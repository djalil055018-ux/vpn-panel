package subscriptioncompat

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func testHost(kind string) Host {
	h := Host{Name: "Synthetic & # profile", Address: "example.test", Port: 443, Protocol: "vless", Transport: kind, Security: "reality",
		ProtocolOptions:  Options{"id": "obsolete-source-credential", "encryption": "none", "flow": ""},
		TransportOptions: Options{}, SecurityOptions: Options{"serverName": "example.test", "publicKey": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "fingerprint": "firefox", "shortId": ""}}
	switch kind {
	case "tcp":
		h.ProtocolOptions["flow"] = "xtls-rprx-vision"
	case "grpc":
		h.TransportOptions = Options{"serviceName": "original/grpc", "authority": "", "multiMode": true}
	case "xhttp":
		h.TransportOptions = Options{"path": "/original?p=1", "mode": "auto", "host": ""}
	case "hysteria":
		h.Protocol, h.Security = "hysteria", "tls"
		h.ProtocolOptions = Options{"version": 2}
		h.TransportOptions = Options{"version": 2, "auth": "obsolete-source-credential"}
		h.SecurityOptions = Options{"serverName": "example.test", "alpn": "h3", "fingerprint": "firefox"}
		h.Stream.FinalMask = Options{"quicParams": Options{"congestion": "bbr", "debug": false}}
	}
	return h
}

func TestSubscriptionCompatibilityCredentialAndTemplate(t *testing.T) {
	credential := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	template := Options{"outbounds": []any{Options{"tag": "direct", "protocol": "freedom"}}, "routing": Options{"rules": []any{Options{"outboundTag": "proxy", "domain": []any{"domain:example.test"}}}}}
	before, _ := json.Marshal(template)
	for _, kind := range []string{"tcp", "grpc", "xhttp", "hysteria"} {
		t.Run(kind, func(t *testing.T) {
			h := testHost(kind)
			for _, format := range []string{"XRAY_BASE64", "XRAY_JSON"} {
				wire, err := Render([]Host{h}, template, format, credential)
				if err != nil {
					t.Fatal("render")
				}
				if format == "XRAY_BASE64" {
					wire, err = base64.StdEncoding.DecodeString(string(wire))
					if err != nil {
						t.Fatal("base64")
					}
					u, e := url.Parse(string(wire))
					if e != nil || u.User.Username() != credential || u.Fragment != h.Name || u.Hostname() != h.Address {
						t.Fatal("URI escaping or credential")
					}
					if kind == "grpc" && u.Query().Get("mode") != "multi" {
						t.Fatal("gRPC multi mode lost")
					}
					if kind == "hysteria" && !json.Valid([]byte(u.Query().Get("fm"))) {
						t.Fatal("Hysteria final mask encoding")
					}
				} else {
					var configs []Options
					if json.Unmarshal(wire, &configs) != nil || len(configs) != 1 || len(configs[0]["outbounds"].([]any)) != 2 {
						t.Fatal("source template lost")
					}
					if kind == "grpc" {
						g := object(object(configs[0]["outbounds"].([]any)[0])["streamSettings"])["grpcSettings"].(map[string]any)
						if g["multiMode"] != true || g["mode"] != nil {
							t.Fatal("Xray gRPC schema")
						}
					}
				}
				if strings.Contains(string(wire), "obsolete-source-credential") || !strings.Contains(string(wire), credential) {
					t.Fatal("credential substitution")
				}
			}
		})
	}
	after, _ := json.Marshal(template)
	if !bytes.Equal(before, after) {
		t.Fatal("shared template mutated")
	}
}

func TestSubscriptionCompatibilitySelection(t *testing.T) {
	credential := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	h := testHost("tcp")
	h.Metadata.Disabled = true
	raw, err := Render([]Host{h}, Options{}, "XRAY_JSON", credential)
	if err != nil || string(raw) != "[]" {
		t.Fatal("disabled host served")
	}
	h.Metadata.Disabled = false
	h.Metadata.Excluded = []string{"XRAY_JSON"}
	raw, err = Render([]Host{h}, Options{}, "XRAY_JSON", credential)
	if err != nil || string(raw) != "[]" {
		t.Fatal("excluded format served")
	}
	for _, kind := range []string{"credential", "endpoint", "transport", "flow", "mapper", "injector", "format"} {
		h := testHost("tcp")
		tpl := Options{}
		format := "XRAY_JSON"
		id := credential
		switch kind {
		case "credential":
			id = "invalid"
		case "endpoint":
			h.Address = "user@host"
		case "transport":
			h.Transport = "unsupported"
		case "flow":
			h.Transport = "grpc"
		case "mapper":
			h.Client.Mapper = Options{"unknown": []any{"mutation"}}
		case "injector":
			tpl["remnawave"] = Options{"unknown": true}
		case "format":
			format = "unknown"
		}
		if _, err := Render([]Host{h}, tpl, format, id); err != ErrProfile {
			t.Fatal("unsupported profile accepted: " + kind)
		}
	}
}

func TestSubscriptionCompatibilityClientFormats(t *testing.T) {
	id := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	hosts := []Host{testHost("tcp"), testHost("grpc"), testHost("xhttp"), testHost("hysteria")}
	hosts[1].TransportOptions["multiMode"] = false
	for i := range hosts {
		hosts[i].Name = hosts[i].Transport
	}
	templates := map[string]Options{
		"SINGBOX": {"outbounds": []any{Options{"type": "direct", "tag": "direct"}, Options{"type": "urltest", "tag": "auto"}, Options{"type": "selector", "tag": "main"}, Options{"type": "selector", "tag": "fixed", "outbounds": []any{"direct"}, "remnawave": Options{"includeProxies": false}}}},
		"MIHOMO":  {"proxy-groups": []any{Options{"name": "main", "proxies": []any{"DIRECT"}}, Options{"name": "fixed", "proxies": []any{"DIRECT"}, "remnawave": Options{"include-proxies": false}}}},
		"STASH":   {"proxy-groups": []any{Options{"name": "main", "proxies": []any{"DIRECT"}}}},
		"CLASH":   {"proxy-groups": []any{Options{"name": "main", "proxies": []any{"DIRECT"}}}},
	}
	for format, tpl := range templates {
		t.Run(format, func(t *testing.T) {
			if format != "SINGBOX" {
				tpl["proxies"] = nil
				tpl["proxy-groups"] = append(tpl["proxy-groups"].([]any), Options{"name": "source-null-group", "proxies": nil})
			}
			before, _ := json.Marshal(tpl)
			raw, err := Render(hosts, tpl, format, id)
			if err != nil {
				t.Fatal("client render")
			}
			var cfg Options
			if json.Unmarshal(raw, &cfg) != nil {
				t.Fatal("structured client profile")
			}
			want := map[string]int{"SINGBOX": 3, "MIHOMO": 4, "STASH": 3, "CLASH": 0}[format]
			if format == "SINGBOX" {
				rows := cfg["outbounds"].([]any)
				count := 0
				for _, row := range rows {
					r := object(row)
					if r["type"] == "vless" || r["type"] == "hysteria2" {
						count++
					}
				}
				if count != want || len(object(rows[1])["outbounds"].([]any)) != 3 || len(object(rows[3])["outbounds"].([]any)) != 1 {
					t.Fatal("Sing-box selection or fixed group changed")
				}
			} else {
				if len(cfg["proxies"].([]any)) != want {
					t.Fatal("client transport capability mismatch")
				}
				groups := cfg["proxy-groups"].([]any)
				if len(object(groups[len(groups)-1])["proxies"].([]any)) != want {
					t.Fatal("source null group was not populated")
				}
				if len(object(groups[0])["proxies"].([]any)) != want+1 {
					t.Fatal("group membership changed")
				}
				if format == "MIHOMO" && len(object(groups[1])["proxies"].([]any)) != 1 {
					t.Fatal("fixed group broadened")
				}
			}
			if strings.Contains(string(raw), "obsolete-source-credential") {
				t.Fatal("old credential exposed")
			}
			after, _ := json.Marshal(tpl)
			if !bytes.Equal(before, after) {
				t.Fatal("shared template changed")
			}
		})
	}
	unsupported := testHost("grpc")
	if _, err := Render([]Host{unsupported}, templates["SINGBOX"], "SINGBOX", id); err != ErrProfile {
		t.Fatal("unsupported gRPC mode silently approximated")
	}
	unsupported = testHost("hysteria")
	unsupported.Stream.FinalMask["quicParams"].(map[string]any)["brutalUp"] = "100mbps"
	if _, err := Render([]Host{unsupported}, templates["MIHOMO"], "MIHOMO", id); err != ErrProfile {
		t.Fatal("unsupported QUIC mask silently lost")
	}
}
