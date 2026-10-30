package botbridge

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) map[string]any {
	t.Helper()
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("fixture JSON")
	}
	for _, u := range v["users"].([]any) {
		u.(map[string]any)["trafficLimitStrategy"] = "NO_RESET"
	}
	users := v["users"].([]any)
	users[0].(map[string]any)["telegramId"] = float64(123456789)
	v["devices"] = []any{map[string]any{"userId": float64(1), "hwid": "synthetic-device-id", "platform": "Android", "osVersion": "14", "deviceModel": nil, "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-02-01T00:00:00Z", "futureSecret": "never-return-device-secret", "requestIp": "192.0.2.1"}}
	return v
}
func parse(t *testing.T, v map[string]any) (Inventory, error) {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return ParseMetadata(raw)
}
func TestMetadataProjectionPreservesNumericIdentityAndDropsCredentials(t *testing.T) {
	out, e := parse(t, fixture(t))
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Users) != 3 || len(out.Squads) != 1 || len(out.Devices) != 1 || out.Users[0].ID != 1 || *out.Users[0].TelegramID != 123456789 || out.Users[0].ShortUUID != "synthetic-source-subscription-1" || out.SubscriptionBase != "https://subscriptions.example.test/" {
		t.Fatal("identity projection mismatch")
	}
	if out.Users[1].HWIDDeviceLimit != nil || out.Users[2].HWIDDeviceLimit == nil || *out.Users[2].HWIDDeviceLimit != 0 {
		t.Fatal("null/unlimited device metadata collapsed")
	}
	raw, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"synthetic-trojan", "synthetic-ss", "11111111-1111", "synthetic-source-subscription", "unmappedCustomMetadata", "futureSecret", "never-return-device-secret", "192.0.2.1"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private source field escaped metadata projection")
		}
	}
}
func TestMetadataRefusesUnsupportedOrAmbiguousSource(t *testing.T) {
	cases := map[string]func(map[string]any){
		"reset policy":        func(v map[string]any) { v["users"].([]any)[0].(map[string]any)["trafficLimitStrategy"] = "DAY" },
		"foreign device":      func(v map[string]any) { v["devices"].([]any)[0].(map[string]any)["userId"] = float64(999) },
		"duplicate device":    func(v map[string]any) { d := v["devices"].([]any); v["devices"] = append(d, d[0]) },
		"missing device date": func(v map[string]any) { delete(v["devices"].([]any)[0].(map[string]any), "updatedAt") },
		"unknown squad": func(v map[string]any) {
			v["users"].([]any)[0].(map[string]any)["activeInternalSquads"] = []any{map[string]any{"uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}}
		},
		"duplicate squad": func(v map[string]any) {
			s := v["internal_squads"].(map[string]any)
			a := s["internalSquads"].([]any)
			s["internalSquads"] = append(a, a[0])
		},
		"mixed sub base": func(v map[string]any) {
			v["users"].([]any)[0].(map[string]any)["subscriptionUrl"] = "https://other.example.test/synthetic-source-subscription-1"
		},
		"alias suffix": func(v map[string]any) {
			v["users"].([]any)[0].(map[string]any)["subscriptionUrl"] = "https://subscriptions.example.test/wrong-alias"
		},
		"query credential": func(v map[string]any) {
			v["users"].([]any)[0].(map[string]any)["subscriptionUrl"] = "https://subscriptions.example.test/synthetic-source-subscription-1?key=secret"
		},
		"telegram shape": func(v map[string]any) { v["users"].([]any)[0].(map[string]any)["telegramId"] = "not-an-id" },
		"metadata bounds": func(v map[string]any) {
			v["users"].([]any)[0].(map[string]any)["description"] = strings.Repeat("x", 4097)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := fixture(t)
			mutate(v)
			if _, e := parse(t, v); e == nil {
				t.Fatal("ambiguous or unsupported metadata accepted")
			}
		})
	}
}

func TestMetadataPreservesImportedDeviceHistory(t *testing.T) {
	v := fixture(t)
	v["devices"].([]any)[0].(map[string]any)["updatedAt"] = "2025-01-01T00:00:00Z"
	out, err := parse(t, v)
	if err != nil || len(out.Devices) != 1 || out.Devices[0].UpdatedAt.Year() != 2025 || out.Devices[0].CreatedAt.Year() != 2026 {
		t.Fatal("imported timestamps must be preserved exactly")
	}
}
