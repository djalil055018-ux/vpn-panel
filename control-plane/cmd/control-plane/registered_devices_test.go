package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLimitedBrowserDoesNotExposeProfiles(t *testing.T) {
	snapshot := publicSubscriptionFixture()
	raw, err := deviceLimitedBrowserBody(snapshot, 2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), snapshot.Credential) || strings.Contains(string(raw), "vless://") || strings.Contains(string(raw), "trojan://") {
		t.Fatal("browser response exposed a VPN profile")
	}
	var value struct {
		Links    []string `json:"links"`
		Limit    int      `json:"deviceLimit"`
		Required bool     `json:"deviceRegistrationRequired"`
	}
	if json.Unmarshal(raw, &value) != nil || len(value.Links) != 0 || value.Limit != 2 || !value.Required {
		t.Fatal("registration information missing")
	}
}
