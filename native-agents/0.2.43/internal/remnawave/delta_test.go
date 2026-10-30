package remnawave

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestDeltaAuditsEveryUserAndSourceCategory(t *testing.T) {
	before := fixture(t)
	m, e := deltaObject(before)
	if e != nil {
		t.Fatal(e)
	}
	users := m["users"].([]any)
	first := users[0].(map[string]any)
	first["trojanPassword"] = "changed-private-password"
	first["status"] = "DISABLED"
	first["expireAt"] = "2027-02-01T00:00:00Z"
	first["trafficLimitStrategy"] = "WEEK"
	first["hwidDeviceLimit"] = 3
	first["activeInternalSquads"] = []any{}
	first["unmappedCustomMetadata"] = map[string]any{"secret": "changed-unknown-private-field"}
	first["userTraffic"].(map[string]any)["usedTrafficBytes"] = json.Number("123457")
	replacement := users[2].(map[string]any)
	replacement["id"] = json.Number("4")
	replacement["username"] = "new-private-name"
	replacement["vlessUuid"] = "44444444-4444-4444-8444-444444444444"
	replacement["shortUuid"] = "new-private-subscription"
	m["devices"] = []any{map[string]any{"hwid": "private-device"}}
	m["hosts"] = []any{map[string]any{"name": "private-host"}}
	m["future_export_field"] = "private-envelope"
	m["captured_at"] = "2026-09-25T21:00:03Z"
	after, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	report, e := Compare(before, after)
	if e != nil {
		t.Fatal(e)
	}
	if report.AddedUsers != 1 || report.RemovedUsers != 1 || report.ChangedUsers != 1 || report.UnchangedUsers != 1 || !report.ReviewRequired || report.CutoverReady || len(report.ChangedCollections) != 3 {
		t.Fatalf("wrong counts: %+v", report)
	}
	for _, key := range []string{"identity_credentials", "status", "expiry", "traffic_limit", "traffic_usage", "hwid_limit", "squads", "other_source_fields"} {
		if report.ChangedCategories[key] != 1 {
			t.Fatalf("missing category %s", key)
		}
	}
	encoded, _ := json.Marshal(report)
	for _, secret := range []string{"changed-private-password", "changed-unknown-private-field", "new-private-name", "new-private-subscription", "private-device", "private-host", "private-envelope", "11111111-1111-4111-8111-111111111111"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("delta exposed source data")
		}
	}
}

func TestDeltaRejectsDifferentSourceAndStaleSnapshots(t *testing.T) {
	before := fixture(t)
	for _, change := range []struct {
		key   string
		value any
	}{{"source_origin", "https://foreign.example.test"}, {"captured_at", "2026-09-25T21:00:01Z"}} {
		m, _ := deltaObject(before)
		m[change.key] = change.value
		after, _ := json.Marshal(m)
		if _, e := Compare(before, after); !errors.Is(e, ErrDeltaSource) {
			t.Fatal("cross-source or stale delta accepted")
		}
	}
	for _, after := range [][]byte{before, append(append([]byte{}, before...), byte('\n'))} {
		r, e := Compare(before, after)
		if e != nil || r.ReviewRequired || r.UnchangedUsers != 3 || r.CutoverReady {
			t.Fatal("unchanged source misreported")
		}
	}
}

func TestDeltaPreservesLargeIntegersAndUnknownFields(t *testing.T) {
	m, _ := deltaObject(fixture(t))
	u := m["users"].([]any)[0].(map[string]any)
	u["futureCounter"] = json.Number("9007199254740992")
	before, _ := json.Marshal(m)
	u["futureCounter"] = json.Number("9007199254740993")
	after, _ := json.Marshal(m)
	r, e := Compare(before, after)
	if e != nil || r.ChangedUsers != 1 || r.ChangedCategories["other_source_fields"] != 1 {
		t.Fatal("large integer delta rounded away")
	}
}
