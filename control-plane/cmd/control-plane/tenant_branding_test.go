package main

import (
	"testing"
	"vpn-platform/internal/model"
)

func TestBrandingValidation(t *testing.T) {
	good := model.TenantBranding{DisplayName: "Мой VPN", Accent: "teal", SupportLabel: "Помощь", SupportURL: "https://support.example/help"}
	if !validBranding(good) {
		t.Fatal("valid branding rejected")
	}
	for _, url := range []string{"javascript:alert(1)", "http://example.org", "https://user:password@example.org", "https://", "https://example.org\\evil", "https://example.org\n"} {
		bad := good
		bad.SupportURL = url
		if validBranding(bad) {
			t.Fatal("unsafe URL accepted")
		}
	}
	bad := good
	bad.Accent = "red;display:none"
	if validBranding(bad) {
		t.Fatal("arbitrary CSS accepted")
	}
	bad = good
	bad.DisplayName = "bad\x00name"
	if validBranding(bad) {
		t.Fatal("control character accepted")
	}
	bad = good
	bad.SupportLabel = ""
	if validBranding(bad) {
		t.Fatal("unlabelled URL accepted")
	}
}
