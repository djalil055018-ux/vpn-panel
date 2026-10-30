package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAmneziaWGProvisioningCapabilityMatchesInstallerMinimum(t *testing.T) {
	a := &application{}
	w := httptest.NewRecorder()
	a.agentCapabilities(w, httptest.NewRequest("GET", "/api/v1/agent/capabilities", nil))
	var value struct {
		Runtimes map[string]struct {
			Minimum      string `json:"minimum_agent"`
			Provisioning bool   `json:"provisioning"`
		} `json:"runtimes"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &value) != nil || value.Runtimes["amneziawg"].Minimum != "0.2.42" || !value.Runtimes["amneziawg"].Provisioning {
		t.Fatal("installer cannot discover guarded AmneziaWG provisioning")
	}
}

func TestAmneziaWGRoutesRequireAuthAndExposeOnlyVersionMetadata(t *testing.T) {
	a := &application{adminToken: "test-only"}
	mux := http.NewServeMux()
	a.registerAmneziaWGRoutes(mux)
	r := httptest.NewRequest("GET", "/api/v1/amneziawg/versions", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("anonymous version registry access")
	}
	r = httptest.NewRequest("GET", "/api/v1/amneziawg/versions", nil)
	r.Header.Set("Authorization", "Bearer test-only")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var got struct {
		Versions []string `json:"versions"`
		Minimum  string   `json:"minimum_agent"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || strings.Join(got.Versions, ",") != "1.0,1.5,2.0,3.0,3.1" || got.Minimum != "0.2.42" {
		t.Fatal("version metadata")
	}
	for _, secret := range []string{"header_protection_key", "private_key", "preshared_key"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("private runtime settings exposed")
		}
	}
}

func TestAmneziaWGConfigurationRejectsMalformedInputBeforeStoreAccess(t *testing.T) {
	a := &application{adminToken: "test-only"}
	mux := http.NewServeMux()
	a.registerAmneziaWGRoutes(mux)
	id := strings.Repeat("a", 8) + "-" + strings.Repeat("a", 4) + "-4aaa-8aaa-" + strings.Repeat("a", 12)
	for name, body := range map[string]string{
		"empty": "{}", "unsupported": `{"version":"9.0"}`, "wrong_type": `{"version":3.1}`,
		"unknown_field": `{"version":"3.1","private_key":"forbidden"}`,
		"extra_object":  `{"version":"3.1"}{}`, "oversize": `{"version":"` + strings.Repeat("x", 2048) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest("PUT", "/api/v1/vpn-services/"+id+"/amneziawg", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer test-only")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatal("malformed input accepted")
			}
		})
	}
	for _, path := range []string{"/api/v1/nodes/invalid/initialize-amneziawg", "/api/v1/vpn-services/invalid/amneziawg"} {
		method := "POST"
		if strings.Contains(path, "vpn-services") {
			method = "GET"
		}
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer test-only")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("invalid identity accepted")
		}
	}
}
