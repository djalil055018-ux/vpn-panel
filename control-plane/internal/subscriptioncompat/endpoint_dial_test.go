package subscriptioncompat

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestEndpointDialXrayPreservesIdentityRoutingAndOtherDNS(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		h := testHost("tcp")
		h.Address = "endpoint.example"
		h.Automatic = automatic
		h.AutoRussiaDirect = automatic
		template := NativeTemplate("XRAY_JSON")
		template["dns"] = Options{"hosts": Options{"unrelated.example": "203.0.113.5"}}
		credential := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		original, err := RenderClient([]Host{h}, template, "XRAY_JSON", credential)
		if err != nil {
			t.Fatal(err)
		}
		h.ConnectRaceIP, h.ConnectRaceAttempts = "192.0.2.10", 16
		raw, err := RenderClient([]Host{h}, template, "XRAY_JSON", credential)
		if err != nil {
			t.Fatal(err)
		}
		var old, current []Options
		json.Unmarshal(original, &old)
		json.Unmarshal(raw, &current)
		for _, key := range []string{"routing", "inbounds", "remarks"} {
			if !reflect.DeepEqual(old[0][key], current[0][key]) {
				t.Fatal("routing or profile identity changed")
			}
		}
		proxy := object(current[0]["outbounds"].([]any)[0])
		before := object(old[0]["outbounds"].([]any)[0])
		if !reflect.DeepEqual(proxy["settings"], before["settings"]) {
			t.Fatal("endpoint or credential changed")
		}
		stream, prior := object(proxy["streamSettings"]), object(before["streamSettings"])
		if !reflect.DeepEqual(stream["realitySettings"], prior["realitySettings"]) {
			t.Fatal("REALITY identity changed")
		}
		hosts := object(object(current[0]["dns"])["hosts"])
		if hosts["unrelated.example"] != "203.0.113.5" || len(hosts["full:endpoint.example"].([]any)) != 16 {
			t.Fatal("DNS scope changed")
		}
		for _, ip := range hosts["full:endpoint.example"].([]any) {
			if ip != "192.0.2.10" {
				t.Fatal("unexpected pinned destination")
			}
		}
		sockopt := object(stream["sockopt"])
		if sockopt["domainStrategy"] != "ForceIPv4" || object(sockopt["happyEyeballs"])["maxConcurrentTry"] != float64(16) {
			t.Fatal("dial policy missing")
		}
	}
}

func TestEndpointDialMetadataCannotBeImportedAndOtherFormatsStayUnchanged(t *testing.T) {
	h := testHost("tcp")
	h.ConnectRaceIP, h.ConnectRaceAttempts = "192.0.2.10", 16
	encoded, _ := json.Marshal(h)
	if bytes.Contains(encoded, []byte("192.0.2.10")) || bytes.Contains(encoded, []byte("connect_race")) {
		t.Fatal("private native metadata leaked into imported-host contract")
	}
	var forged Host
	json.Unmarshal([]byte(`{"ConnectRaceIP":"192.0.2.10","connect_race_ip":"192.0.2.10","connect_race_attempts":16}`), &forged)
	if forged.ConnectRaceIP != "" || forged.ConnectRaceAttempts != 0 {
		t.Fatal("import supplied native dial policy")
	}
	for _, format := range []string{"XRAY_BASE64", "SINGBOX", "MIHOMO"} {
		before := h
		before.ConnectRaceIP = ""
		before.ConnectRaceAttempts = 0
		a, err := RenderClient([]Host{before}, NativeTemplate(format), format, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
		if err != nil {
			t.Fatal(err)
		}
		b, err := RenderClient([]Host{h}, NativeTemplate(format), format, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatal("unrelated format changed")
		}
	}
	h.ConnectRaceAttempts = 17
	if _, err := RenderClient([]Host{h}, NativeTemplate("XRAY_JSON"), "XRAY_JSON", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"); err == nil {
		t.Fatal("unbounded public dial policy accepted")
	}
}
