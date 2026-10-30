package subscriptioncompat

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestSubscriptionBrowserByteOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/browser-bytes.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Bytes    int64  `json:"bytes"`
		Expected string `json:"expected"`
	}
	if json.Unmarshal(raw, &cases) != nil || len(cases) < 200 {
		t.Fatal("byte oracle missing")
	}
	for _, c := range cases {
		if got := browserBytes(c.Bytes); got != c.Expected {
			t.Fatalf("bytes %d: got %s want %s", c.Bytes, got, c.Expected)
		}
	}
}
func TestSubscriptionBrowserAccessAndMetadata(t *testing.T) {
	now := time.Date(2026, 9, 27, 1, 0, 0, 0, time.UTC)
	p := policyFixture()
	a := ResponseAccount{Alias: "synthetic-subscription", Username: "synthetic-user", SubscriptionURL: "https://example.test/synthetic-subscription",
		ExpiresAt: now.Add(36 * time.Hour), UsedBytes: 1152, LifetimeBytes: 1536, LimitBytes: 100000, Status: "ACTIVE"}
	credential := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	hosts := []Host{testHost("tcp")}
	for _, status := range []string{"ACTIVE", "EXPIRED", "DISABLED", "LIMITED"} {
		a.Status = status
		raw, err := BrowserInfo(p, a, hosts, credential, now)
		if err != nil {
			t.Fatal("browser render")
		}
		var result struct {
			User  map[string]any `json:"user"`
			Links []string       `json:"links"`
		}
		if json.Unmarshal(raw, &result) != nil || result.User["daysLeft"] != float64(1) || result.User["trafficUsed"] != "1.13 KiB" || result.User["trafficUsedBytes"] != "1152" || result.User["lifetimeTrafficUsedBytes"] != "1536" {
			t.Fatal("browser accounting")
		}
		if (status == "ACTIVE") != bytes.Contains(raw, []byte(credential)) {
			t.Fatal("browser native credential boundary")
		}
		if status != "ACTIVE" && (bytes.Contains(raw, []byte("example.test:443")) || len(result.Links) != 1) {
			t.Fatal("inactive browser endpoint")
		}
	}
	a.ExpiresAt = now.Add(-35 * time.Hour)
	raw, err := BrowserInfo(p, a, hosts, credential, now)
	if err != nil || !bytes.Contains(raw, []byte(`"daysLeft":-1`)) {
		t.Fatal("expired day truncation")
	}
}
