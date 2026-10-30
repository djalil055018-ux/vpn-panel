package clientdirectory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func fixture() map[string]any {
	return map[string]any{"captured_at": "2026-10-04T12:00:00Z", "nodes": []any{map[string]any{"uuid": "fixture-node", "name": "Netherlands"}}, "users": []any{map[string]any{
		"id": 145, "telegramId": 123456789, "status": "ACTIVE", "tag": "friends", "lastTrafficResetAt": nil,
		"activeInternalSquads": []any{map[string]any{"name": "Основная", "uuid": "SECRET-GROUP-REFERENCE"}},
		"userTraffic":          map[string]any{"firstConnectedAt": "2026-09-01T10:00:00Z", "onlineAt": "2026-10-04T11:59:59Z", "lastConnectedNodeUuid": "fixture-node", "lifetimeUsedTrafficBytes": 1024},
		"vlessUuid":            "SECRET-VLESS", "trojanPassword": "SECRET-TROJAN", "subscriptionUrl": "SECRET-SUBSCRIPTION", "unexpected": map[string]any{"key": "SECRET-FUTURE"},
	}}}
}
func project(t *testing.T, value map[string]any) (map[int64]json.RawMessage, error) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	rows, err := ProjectSnapshot(raw, hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}
	result := map[int64]json.RawMessage{}
	for id, row := range rows {
		result[id], err = json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
	}
	return result, nil
}
func TestSnapshotProjectionAllowlist(t *testing.T) {
	rows, err := project(t, fixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || bytes.Contains(rows[145], []byte("SECRET")) {
		t.Fatal("private source data escaped projection")
	}
	var row map[string]any
	if json.Unmarshal(rows[145], &row) != nil {
		t.Fatal("invalid projection")
	}
	if row["telegram_id"] != "123456789" || row["last_node_name"] != "Netherlands" || row["connection_state"] != "unknown" || row["lifetime_used_bytes"] != float64(1024) {
		t.Fatal("display metadata missing or snapshot advertised as live")
	}
	if value, present := row["last_traffic_reset_at"]; !present || value != nil {
		t.Fatal("explicit never-reset observation lost")
	}
}
func TestUnknownAndNeverAreDifferent(t *testing.T) {
	value := fixture()
	user := value["users"].([]any)[0].(map[string]any)
	traffic := user["userTraffic"].(map[string]any)
	delete(traffic, "firstConnectedAt")
	delete(traffic, "onlineAt")
	delete(user, "lastTrafficResetAt")
	rows, err := project(t, value)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"first_connected_at", "last_online_at", "last_traffic_reset_at"} {
		if bytes.Contains(rows[145], []byte(field)) {
			t.Fatal("unknown observation became never")
		}
	}
	traffic["firstConnectedAt"] = nil
	traffic["onlineAt"] = nil
	rows, err = project(t, value)
	if err != nil || !bytes.Contains(rows[145], []byte(`"connection_state":"never"`)) {
		t.Fatal("explicit unconnected user lost")
	}
}
func TestSnapshotRejectsTamperingAndInvalidMetadata(t *testing.T) {
	raw, _ := json.Marshal(fixture())
	if _, err := ProjectSnapshot(raw, "00"); err == nil {
		t.Fatal("unverified source accepted")
	}
	for _, change := range []func(map[string]any){
		func(u map[string]any) { u["id"] = 0 }, func(u map[string]any) { u["status"] = "UNKNOWN" },
		func(u map[string]any) { u["telegramId"] = -1 }, func(u map[string]any) { u["tag"] = "bad\x00tag" },
		func(u map[string]any) { u["lastTrafficResetAt"] = "yesterday" },
		func(u map[string]any) { u["userTraffic"].(map[string]any)["lifetimeUsedTrafficBytes"] = -1 },
	} {
		value := fixture()
		change(value["users"].([]any)[0].(map[string]any))
		if _, err := project(t, value); err == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
}
