package model

import (
	"strings"
	"testing"
)

func TestSubscriptionDisplayName(t *testing.T) {
	c := VPNClientConnection{BrandName: "PAUK", ServiceName: "Nid Xhttp"}
	if c.DisplayName() != "PAUK - Nid Xhttp" {
		t.Fatal("existing label changed")
	}
	c.SubscriptionName = "🇳🇱 Нидерланды · XHTTP & #1"
	if c.DisplayName() != c.SubscriptionName {
		t.Fatal("custom name must be exact, without branding prefix")
	}
	for _, name := range []string{"", c.SubscriptionName, strings.Repeat("界", 200), "👨‍👩‍👧‍👦 Семья"} {
		if !ValidSubscriptionName(name) {
			t.Fatal("valid Unicode label rejected")
		}
	}
	for _, name := range []string{"one\ntwo", "one\rtwo", "one\ttwo", "one\x00two", "one\u2028two", "one\u2029two", strings.Repeat("界", 201), string([]byte{0xff})} {
		if ValidSubscriptionName(name) {
			t.Fatal("invalid label accepted")
		}
	}
}
