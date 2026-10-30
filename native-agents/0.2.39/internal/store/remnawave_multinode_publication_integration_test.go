//go:build integration

package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
	"vpn-platform/internal/subscriptioncompat"
)

// Real owner preparation from source-shaped inventory/settings, with three
// registered native nodes. Health and physical receipts remain synthetic.
func TestRemnawaveMultiNodePublicationIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "Synthetic three-node publication")
	check(err)
	raw, err := os.ReadFile("../remnawave/testdata/inventory.json")
	check(err)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	frozen := time.Now().UTC().Add(-2 * time.Second).Truncate(time.Microsecond)
	inv["source_origin"] = "https://three-node-" + tenant.ID + ".example.test"
	inv["started_at"] = frozen
	inv["captured_at"] = frozen.Add(time.Second)
	for _, v := range inv["users"].([]any) {
		u := v.(map[string]any)
		u["trafficLimitStrategy"] = "NO_RESET"
		u["activeInternalSquads"] = inv["users"].([]any)[0].(map[string]any)["activeInternalSquads"]
	}
	profileID, inboundID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1", "cccccccc-cccc-4ccc-8ccc-ccccccccccc1"
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	inbound := map[string]any{"tag": "raw", "protocol": "vless", "listen": "0.0.0.0", "port": 443, "settings": map[string]any{"clients": []any{}, "decryption": "none", "flow": ""}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"target": "synthetic.example.test:443", "serverNames": []string{"synthetic.example.test"}, "shortIds": []string{""}, "privateKey": key}}}
	meta := []any{map[string]any{"uuid": inboundID, "profileUuid": profileID, "tag": "raw", "type": "vless", "network": "raw", "security": "reality", "port": 443, "rawInbound": inbound}}
	sourceIDs := []string{}
	sourceNodes, profileNodes := []any{}, []any{}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", i+1)
		sourceIDs = append(sourceIDs, id)
		sourceNodes = append(sourceNodes, map[string]any{"uuid": id, "isDisabled": false, "activePluginUuid": nil, "proxyUrl": nil, "consumptionMultiplier": 1, "nodeConsumptionMultiplier": 1, "configProfile": map[string]any{"activeConfigProfileUuid": profileID, "activeInbounds": meta}})
		profileNodes = append(profileNodes, map[string]any{"uuid": id})
	}
	inv["nodes"] = sourceNodes
	inv["config_profiles"] = map[string]any{"configProfiles": []any{map[string]any{"uuid": profileID, "config": map[string]any{"inbounds": []any{inbound}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}}, "inbounds": meta, "nodes": profileNodes}}}
	inv["internal_squads"].(map[string]any)["internalSquads"].([]any)[0].(map[string]any)["inbounds"] = meta
	inv["hosts"] = []any{map[string]any{"uuid": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", "remark": "Synthetic shared host", "address": "synthetic-profile.example.test", "port": 443, "viewPosition": 1, "inbound": map[string]any{"configProfileUuid": profileID, "configProfileInboundUuid": inboundID}, "isDisabled": false, "isHidden": false, "shuffleHost": false, "keepSniBlank": false, "overrideSniFromAddress": false, "mihomoX25519": false, "securityLayer": "DEFAULT", "fingerprint": "firefox", "nodes": []any{}, "excludeFromSubscriptionTypes": []any{}, "internalSquads": map[string]any{"mode": "EXCLUDE", "squads": []any{}}}}
	raw, err = json.Marshal(inv)
	check(err)
	_, review, err := remnawave.Parse(raw)
	check(err)
	imported, _, err := p.StageRemnawaveInventory(ctx, tenant.ID, raw, review.SHA256)
	check(err)
	_, err = p.PrepareRemnawaveNoResetQuota(ctx, imported.ID, tenant.ID, review.SHA256)
	check(err)
	_, err = p.PrepareBotBridge(ctx, tenant.ID, imported.ID, review.SHA256)
	check(err)
	nativeNodes := []string{}
	request := RemnawaveCutoverRequest{TenantID: tenant.ID, InventorySHA256: review.SHA256, SourceFreezeSHA256: strings.Repeat("c", 64), SourceFrozenAt: frozen, RollbackDeadline: time.Now().UTC().Add(10 * time.Minute)}
	for i, sourceID := range sourceIDs {
		bootstrap := security.HashToken(fmt.Sprintf("synthetic-multi-bootstrap-%d", i))
		node, e := p.CreateNodeForRuntime(ctx, tenant.ID, fmt.Sprintf("Synthetic node %d", i), bootstrap, "xray")
		check(e)
		_, e = p.PrepareXrayProfile(ctx, tenant.ID, imported.ID, node.ID, sourceID, review.SHA256, nil)
		check(e)
		_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken(fmt.Sprintf("synthetic-multi-agent-%d", i)), "0.2.31", "ubuntu", "24.04", "amd64", "xray")
		check(e)
		nativeNodes = append(nativeNodes, node.ID)
		request.Nodes = append(request.Nodes, RemnawaveNodeHandoff{NodeID: node.ID, MaterialSHA256: strings.Repeat("d", 64), HandoffSHA256: strings.Repeat("e", 64), SourceStopped: true, SourceRestartFenced: true, MaterialPublished: true, RollbackArmed: true})
	}
	settings := syntheticCutoverSettings(t, inv["source_origin"].(string))
	sum := sha256.Sum256(settings)
	settingsSHA := hex.EncodeToString(sum[:])
	prepared, err := p.PrepareImportedSubscriptions(ctx, tenant.ID, imported.ID, review.SHA256, settingsSHA, settings)
	check(err)
	replay, err := p.PrepareImportedSubscriptions(ctx, tenant.ID, imported.ID, review.SHA256, settingsSHA, settings)
	check(err)
	if !reflect.DeepEqual(prepared, replay) || prepared.Hosts != 1 || prepared.Squads != 1 || prepared.Templates != 5 || prepared.State != "prepared" {
		t.Fatal("real public preparation incomplete or non-idempotent")
	}
	request.SubscriptionRevisionID = prepared.RevisionID
	request.BundleSHA256 = prepared.BundleSHA256
	_, err = p.PrepareBotSquadPlans(ctx, tenant.ID, imported.ID, review.SHA256, prepared.RevisionID, prepared.BundleSHA256)
	check(err)
	release, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.9.9", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/multi.zip", SHA256: strings.Repeat("b", 64), Channel: "testing"})
	check(err)
	check(p.ApproveCoreRelease(ctx, release.ID))
	request.CoreReleaseID = release.ID
	cutover, err := p.BeginRemnawaveRuntimeCutover(ctx, imported.ID, request)
	check(err)
	if len(cutover.Nodes) != 3 || cutover.State != "verifying" {
		t.Fatal("three-node runtime cutover incomplete")
	}
	publication := RemnawavePublicationRequest{TenantID: tenant.ID, RuntimeRequestSHA256: cutover.RequestSHA256}
	for _, id := range nativeNodes {
		desired, exists, e := p.LatestDesiredState(ctx, id)
		check(e)
		if !exists || desired.Generation != 1 || len(desired.Services) != 1 || len(desired.Services[0].Clients) != 1 {
			t.Fatal("wrong native node eligibility")
		}
		publication.Nodes = append(publication.Nodes, RemnawavePublicationNode{NodeID: id, Generation: 1, ProfileSHA256: desired.XrayProfile.SHA256, ServiceIDs: []string{desired.Services[0].ID}, ExternalProofSHA256: strings.Repeat("a", 64), GuardCommitSHA256: strings.Repeat("f", 64), GuardCommittedAt: time.Now().UTC(), SourceStillFenced: true})
	}
	// Every node must converge: one missing final report blocks the whole publish.
	for i, id := range nativeNodes {
		if i == 2 {
			publication.VerifiedAt = time.Now().UTC()
			if _, e := p.PublishRemnawaveCutover(ctx, imported.ID, publication); !errors.Is(e, ErrRemnawaveCutover) {
				t.Fatalf("partial convergence accepted: %v", e)
			}
		}
		_, err = p.Pool.Exec(ctx, `UPDATE nodes SET status='online',last_seen_at=now(),applied_generation=1 WHERE id=$1::uuid`, id)
		check(err)
		_, err = p.Pool.Exec(ctx, `UPDATE deployments SET status='healthy',completed_at=now(),applied_core_version=$2 WHERE node_id=$1::uuid`, id, release.Version)
		check(err)
		_, err = p.Pool.Exec(ctx, `INSERT INTO node_health(node_id,healthy,applied_generation,core,core_version,message,checked_at) VALUES($1::uuid,true,1,'xray',$2,'synthetic multihost fixture',clock_timestamp()) ON CONFLICT(node_id) DO UPDATE SET healthy=true,applied_generation=1,core='xray',core_version=excluded.core_version,checked_at=excluded.checked_at`, id, release.Version)
		check(err)
	}
	publication.VerifiedAt = time.Now().UTC()
	missing := publication
	missing.Nodes = publication.Nodes[:2]
	if _, err = p.PublishRemnawaveCutover(ctx, imported.ID, missing); !errors.Is(err, ErrRemnawaveCutover) {
		t.Fatal("missing node proof accepted")
	}
	// Native traffic accrued during verification must survive publication.
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_client_continuous_quotas q SET uplink_bytes=uplink_bytes+17 FROM bot_accounts b WHERE b.client_id=q.client_id AND b.tenant_id=$1::uuid AND b.legacy_id=1`, tenant.ID)
	check(err)
	published, err := p.PublishRemnawaveCutover(ctx, imported.ID, publication)
	check(err)
	if published.PhysicalProof != "owner_attestation" {
		t.Fatal("synthetic physical proof overclaimed")
	}
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	status, err := p.BotBridgeStatus(operator)
	check(err)
	if !status.MigrationReady {
		t.Fatal("three-node bridge not ready")
	}
	var alias string
	check(p.Pool.QueryRow(ctx, `SELECT alias FROM bot_subscription_aliases WHERE tenant_id=$1::uuid AND legacy_id=1 AND state='active'`, tenant.ID).Scan(&alias))
	snap, err := p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: alias})
	check(err)
	if len(snap.Hosts) != 1 || len(snap.Templates) != 5 {
		t.Fatal("prepared source projection not publicly readable")
	}
	rendered, err := subscriptioncompat.Render(snap.Hosts, snap.Templates["XRAY_JSON"].Body, "XRAY_JSON", snap.Credential)
	check(err)
	if len(rendered) == 0 {
		t.Fatal("empty public profile")
	}
	var used int64
	check(p.Pool.QueryRow(ctx, `SELECT baseline_bytes+uplink_bytes+downlink_bytes FROM vpn_client_continuous_quotas q JOIN bot_accounts b ON b.client_id=q.client_id WHERE b.tenant_id=$1::uuid AND b.legacy_id=1`, tenant.ID).Scan(&used))
	if used != 123473 {
		t.Fatal("publication rewound native accounting")
	}
	var generations int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM desired_states ds JOIN nodes n ON n.id=ds.node_id WHERE n.tenant_id=$1::uuid`, tenant.ID).Scan(&generations))
	if generations != 3 {
		t.Fatal("publication changed runtime generations")
	}
	// Reordering an identical proof retains its canonical publication identity.
	publication.Nodes[0], publication.Nodes[2] = publication.Nodes[2], publication.Nodes[0]
	again, err := p.PublishRemnawaveCutover(ctx, imported.ID, publication)
	check(err)
	if again != published {
		t.Fatal("node order changed publication identity")
	}
}

func syntheticCutoverSettings(t *testing.T, origin string) []byte {
	t.Helper()
	remarks := map[string][]string{}
	for _, key := range []string{"HWIDMaxDevicesExceeded", "HWIDNotSupported", "disabledUsers", "emptyHosts", "expiredUsers", "limitedUsers"} {
		remarks[key] = []string{key}
	}
	global := map[string]any{"uuid": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "custom_remarks": remarks, "custom_response_headers": map[string]string{"profile-title": "Synthetic migration"}, "hwid_settings": map[string]any{"enabled": false, "fallbackDeviceLimit": 2}, "is_show_custom_remarks": true, "randomize_hosts": false, "serve_json_at_base_subscription": true, "response_rules": map[string]any{"version": "1", "rules": []any{map[string]any{"name": "fallback", "enabled": true, "operator": "AND", "responseType": "XRAY_BASE64", "conditions": []any{}}}}}
	templates := []any{}
	for i, format := range []string{"XRAY_JSON", "SINGBOX", "MIHOMO", "STASH", "CLASH"} {
		row := map[string]any{"uuid": fmt.Sprintf("dddddddd-dddd-4ddd-8ddd-%012d", i+1), "name": "Default", "template_type": format, "template_json": nil, "template_yaml": nil}
		switch format {
		case "XRAY_JSON":
			row["template_json"] = map[string]any{"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}}}
		case "SINGBOX":
			row["template_json"] = map[string]any{"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}, map[string]any{"type": "selector", "tag": "Select", "outbounds": nil}}}
		default:
			row["template_yaml"] = "proxies: null\nproxy-groups:\n  - name: Select\n    type: select\n    proxies: null\n"
		}
		templates = append(templates, row)
	}
	raw, err := json.Marshal(map[string]any{"format": 1, "kind": "remnawave_subscription_settings_snapshot", "source_origin": origin, "captured_at": time.Now().UTC(), "tables": map[string]any{"subscription_settings": []any{global}, "subscription_page_config": []any{map[string]any{"uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "name": "Default", "view_position": 1, "config": map[string]any{"version": "synthetic"}}}, "subscription_templates": templates}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
