package remnawave

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	raw, e := os.ReadFile("testdata/inventory.json")
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestInventoryPreservationAndSafeReport(t *testing.T) {
	raw := fixture(t)
	inv, r, e := Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(inv.Users) != 3 || r.Users != 3 || r.CutoverReady || r.LimitedUsers != 2 || r.HWIDLimitedUsers != 1 || len(r.RequiredReview) != 6 || r.IndependentTrojanCredentials != 3 {
		t.Fatal("inventory summary lost source semantics")
	}
	encoded, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{inv.Users[0].TrojanPassword, inv.Users[0].SSPassword, inv.Users[0].VLESSUUID, inv.Users[0].ShortUUID, inv.Users[0].SubscriptionURL, inv.Users[0].Username} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("report disclosed source user information")
		}
	}
	if !bytes.Contains(raw, []byte(`"unmappedCustomMetadata"`)) {
		t.Fatal("fixture lacks unknown-field preservation oracle")
	}
}
func TestInventoryPreservesImportedSourceTimestampOrder(t *testing.T) {
	var m map[string]any
	if e := json.Unmarshal(fixture(t), &m); e != nil {
		t.Fatal(e)
	}
	user := m["users"].([]any)[0].(map[string]any)
	user["createdAt"] = "2026-09-20T12:00:00Z"
	user["updatedAt"] = "2026-08-15T12:00:00Z"
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	before := append([]byte{}, raw...)
	inv, report, e := Parse(raw)
	if e != nil {
		t.Fatal("valid source history rejected", e)
	}
	created, _ := time.Parse(time.RFC3339, user["createdAt"].(string))
	updated, _ := time.Parse(time.RFC3339, user["updatedAt"].(string))
	if !inv.Users[0].CreatedAt.Equal(created) || !inv.Users[0].UpdatedAt.Equal(updated) || !bytes.Equal(raw, before) || report.Users != 3 || report.CutoverReady {
		t.Fatal("source timestamps or held-only semantics changed")
	}
}
func TestInventoryRejectsIncompleteOrAmbiguousInput(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"version":            func(m map[string]any) { m["contract_version"] = "3.5.0" },
		"source-http":        func(m map[string]any) { m["source_origin"] = "http://example.test" },
		"source-credentials": func(m map[string]any) { m["source_origin"] = "https://secret@example.test" },
		"source-path":        func(m map[string]any) { m["source_origin"] = "https://example.test/api" },
		"missing-users":      func(m map[string]any) { delete(m, "users") },
		"missing-config":     func(m map[string]any) { delete(m, "config_profiles") },
		"total":              func(m map[string]any) { m["verification"].(map[string]any)["source_total"] = 4 },
		"passes":             func(m map[string]any) { m["verification"].(map[string]any)["stable_user_passes"] = 1 },
		"duplicate-id":       func(m map[string]any) { users := m["users"].([]any); users[1].(map[string]any)["id"] = float64(1) },
		"duplicate-vless-case": func(m map[string]any) {
			users := m["users"].([]any)
			users[1].(map[string]any)["vlessUuid"] = users[0].(map[string]any)["vlessUuid"]
		},
		"invalid-status":  func(m map[string]any) { m["users"].([]any)[0].(map[string]any)["status"] = "UNKNOWN" },
		"missing-counter": func(m map[string]any) { delete(m["users"].([]any)[0].(map[string]any), "userTraffic") },
		"negative-counter": func(m map[string]any) {
			m["users"].([]any)[0].(map[string]any)["userTraffic"].(map[string]any)["usedTrafficBytes"] = -1
		},
		"fractional-counter":        func(m map[string]any) { m["users"].([]any)[0].(map[string]any)["trafficLimitBytes"] = 1.5 },
		"missing-password":          func(m map[string]any) { delete(m["users"].([]any)[0].(map[string]any), "trojanPassword") },
		"missing-updated-timestamp": func(m map[string]any) { delete(m["users"].([]any)[0].(map[string]any), "updatedAt") },
		"zero-updated-timestamp":    func(m map[string]any) { m["users"].([]any)[0].(map[string]any)["updatedAt"] = "0001-01-01T00:00:00Z" },
		"unsupported-reset":         func(m map[string]any) { m["users"].([]any)[0].(map[string]any)["trafficLimitStrategy"] = "YEAR" },
		"credential-newline":        func(m map[string]any) { m["users"].([]any)[0].(map[string]any)["ssPassword"] = "password\ninjected" },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			if json.Unmarshal(fixture(t), &m) != nil {
				t.Fatal("fixture")
			}
			mutate(m)
			raw, _ := json.Marshal(m)
			if _, _, e := Parse(raw); e == nil {
				t.Fatal("invalid source admitted")
			}
		})
	}
	raw := fixture(t)
	for name, value := range map[string][]byte{
		"duplicate-field": bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1),
		"trailing-object": append(append([]byte{}, raw...), []byte(`{}`)...),
		"deep-nesting":    []byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66)),
		"invalid-utf8":    append(raw, 255),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, e := Parse(value); e == nil {
				t.Fatal("ambiguous input admitted")
			}
		})
	}
}
