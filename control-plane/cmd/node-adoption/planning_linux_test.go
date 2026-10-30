package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"vpn-platform/internal/nodeadoption"
	"vpn-platform/internal/xrayprofile"
)

func TestCLIReviewedPlanningThroughStage(t *testing.T) {
	root := t.TempDir()
	host, _ := os.Hostname()
	id := "11111111-1111-4111-8111-111111111111"
	sourceID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	profileID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	private := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{61}, 32))
	inbound := map[string]any{"tag": "raw", "protocol": "vless", "listen": "0.0.0.0", "port": 443, "settings": map[string]any{"clients": []any{}, "decryption": "none"}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"dest": "example.org:443", "serverNames": []string{"example.org"}, "shortIds": []string{""}, "privateKey": private}}}
	raw, e := os.ReadFile("../../internal/remnawave/testdata/inventory.json")
	if e != nil {
		t.Fatal("fixture inventory")
	}
	var inv map[string]any
	if json.Unmarshal(raw, &inv) != nil {
		t.Fatal("fixture JSON")
	}
	metadata := []any{map[string]any{"uuid": id, "profileUuid": profileID, "tag": "raw", "type": "vless", "network": "raw", "security": "reality", "port": 443, "rawInbound": inbound}}
	inv["nodes"] = []any{map[string]any{"uuid": sourceID, "isDisabled": false, "activePluginUuid": nil, "proxyUrl": nil, "consumptionMultiplier": 1, "nodeConsumptionMultiplier": 1, "configProfile": map[string]any{"activeConfigProfileUuid": profileID, "activeInbounds": metadata}}}
	inv["config_profiles"] = map[string]any{"configProfiles": []any{map[string]any{"uuid": profileID, "config": map[string]any{"inbounds": []any{inbound}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}}, "inbounds": metadata, "nodes": []any{map[string]any{"uuid": sourceID}}}}}
	inventory, _ := json.Marshal(inv)
	sum := sha256.Sum256(inventory)
	reviewed := hex.EncodeToString(sum[:])
	req := nodeadoption.PlanningRequest{Version: 1, TenantID: id, ImportID: id, NodeID: id, SourceNodeID: sourceID, ReviewedSHA256: reviewed, ExpectedHostname: host}
	request, _ := json.Marshal(req)
	for name, data := range map[string][]byte{"request": request, "inventory": inventory, "certificates": []byte("[]")} {
		if os.WriteFile(root+"/"+name, data, 0600) != nil {
			t.Fatal("fixture write")
		}
	}
	run := func(args ...string) {
		t.Helper()
		var out, err bytes.Buffer
		if execute(args, &out, &err, 0) != 0 {
			t.Fatal("planning CLI action failed: " + args[0])
		}
		if bytes.Contains(out.Bytes(), []byte(private)) || bytes.Contains(out.Bytes(), []byte(sourceID)) || err.Len() != 0 {
			t.Fatal("private CLI output")
		}
	}
	run("plan-inspection", "--plan", root+"/request", "--inventory", root+"/inventory", "--out", root+"/inspection-plan")
	run("inspect", "--plan", root+"/inspection-plan/inspection-plan.json", "--config", root+"/inspection-plan/source-config.json", "--out", root+"/inspection")
	run("plan-preparation", "--plan", root+"/request", "--inventory", root+"/inventory", "--inspection", root+"/inspection/inspection.json", "--certificates", root+"/certificates", "--out", root+"/preparation-plan")
	projected, e := xrayprofile.ProjectSourceNode(inventory, sourceID, []xrayprofile.SourceServiceAssignment{{InboundID: id, ServiceID: id}})
	if e != nil {
		t.Fatal("prepared fixture")
	}
	prepared := nodeadoption.Preparation{NodeID: id, ImportID: id, InventorySHA256: reviewed, ReviewedSHA256: reviewed, ProfileSHA256: projected.Profile.SHA256, Services: projected.Services, State: "prepared"}
	data, _ := json.Marshal(prepared)
	if os.WriteFile(root+"/prepared", data, 0600) != nil {
		t.Fatal("fixture preparation")
	}
	run("plan-stage", "--plan", root+"/request", "--inventory", root+"/inventory", "--inspection", root+"/inspection/inspection.json", "--certificates", root+"/certificates", "--preparation", root+"/prepared", "--out", root+"/stage-plan")
	run("stage", "--plan", root+"/stage-plan/stage-plan.json", "--config", root+"/stage-plan/source-config.json", "--out", root+"/stage")
	key, e := os.ReadFile(root + "/stage/node-data/secrets/reality/" + id + ".key")
	if e != nil || string(key) != private+"\n" {
		t.Fatal("original key was not carried through the full CLI chain")
	}
}
