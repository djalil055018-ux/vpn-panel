//go:build integration

package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
)

func TestXrayProfileOwnerPreparationIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, e := p.CreateTenant(ctx, "Synthetic source preparation")
	check(e)
	node, e := p.CreateNodeForRuntime(ctx, tenant.ID, "Unused imported node", security.HashToken("synthetic-prepare-node"), "xray")
	check(e)
	cert, e := p.CreateNodeCertificate(ctx, node.ID, "profile.example.test", "letsencrypt", "http-01", "production", nil, true)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_before=now()-interval '1 day',not_after=now()+interval '1 day' WHERE id=$1::uuid`, cert.ID)
	check(e)
	sourceNode, sourceProfile := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	check(e)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	inv["source_origin"] = "https://" + strings.ToLower(t.Name()) + ".example.test"
	inv["users"] = []any{}
	inv["devices"] = []any{}
	inv["verification"].(map[string]any)["source_total"] = 0
	inv["verification"].(map[string]any)["unique_user_ids"] = 0
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	inbound := map[string]any{"tag": "raw", "protocol": "vless", "listen": "0.0.0.0", "port": 443, "settings": map[string]any{"clients": []any{}, "decryption": "none"},
		"streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"target": "/run/source/front.sock", "serverNames": []string{"profile.example.test"}, "shortIds": []string{""}, "privateKey": key, "xver": 1}}}
	hys := map[string]any{"tag": "hys", "protocol": "hysteria", "listen": "0.0.0.0", "port": 443, "settings": map[string]any{"clients": []any{}, "version": 2},
		"streamSettings": map[string]any{"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2}, "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": "/source/cert.pem", "keyFile": "/source/key.pem"}}}}}
	inbounds := []any{inbound, hys}
	metadata := []any{}
	for i, v := range inbounds {
		in := v.(map[string]any)
		s := in["streamSettings"].(map[string]any)
		metadata = append(metadata, map[string]any{"uuid": fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012d", i+1), "profileUuid": sourceProfile, "tag": in["tag"], "type": in["protocol"], "network": s["network"], "security": s["security"], "port": in["port"], "rawInbound": in})
	}
	inv["nodes"] = []any{map[string]any{"uuid": sourceNode, "isDisabled": false, "activePluginUuid": nil, "proxyUrl": nil, "consumptionMultiplier": 1, "nodeConsumptionMultiplier": 1, "configProfile": map[string]any{"activeConfigProfileUuid": sourceProfile, "activeInbounds": metadata[:1]}}}
	inv["config_profiles"] = map[string]any{"configProfiles": []any{map[string]any{"uuid": sourceProfile, "config": map[string]any{"inbounds": inbounds, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}}, "inbounds": metadata, "nodes": []any{map[string]any{"uuid": sourceNode}}}}}
	raw, e = json.Marshal(inv)
	check(e)
	_, report, e := remnawave.Parse(raw)
	check(e)
	imported, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, report.SHA256)
	check(e)
	tls := []XrayProfileTLSAssignment{{SourceInboundID: metadata[1].(map[string]any)["uuid"].(string), CertificateID: cert.ID}}
	prepare := func(tls []XrayProfileTLSAssignment, sha string) (XrayProfilePreparation, error) {
		return p.PrepareXrayProfile(ctx, tenant.ID, imported.ID, node.ID, sourceNode, sha, tls)
	}
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	if _, e = p.PrepareXrayProfile(operator, tenant.ID, imported.ID, node.ID, sourceNode, report.SHA256, tls); !errors.Is(e, ErrNotFound) {
		t.Fatal("tenant token prepared an owner import")
	}
	if _, e = prepare(tls, strings.Repeat("0", 64)); !errors.Is(e, ErrRemnawaveReview) {
		t.Fatal("unreviewed source prepared")
	}
	if _, e = prepare(nil, report.SHA256); !errors.Is(e, ErrVPNServiceTLSInvalid) {
		t.Fatal("missing certificate prepared")
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM node_xray_profiles WHERE node_id=$1::uuid`, node.ID).Scan(&count))
	if count != 0 {
		t.Fatal("failed preparation partially committed")
	}
	const calls = 4
	var wg sync.WaitGroup
	results := make(chan XrayProfilePreparation, calls)
	failures := make(chan error, calls)
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); out, err := prepare(tls, report.SHA256); results <- out; failures <- err }()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		check(err)
	}
	var first XrayProfilePreparation
	for out := range results {
		if first.NodeID == "" {
			first = out
		} else if !reflect.DeepEqual(first, out) {
			t.Fatal("concurrent retry duplicated identities")
		}
	}
	if first.State != "prepared" || len(first.Services) != 2 || !first.Services[0].Enabled || first.Services[1].Enabled || first.InventorySHA256 != report.SHA256 || first.ReviewedSHA256 != report.SHA256 {
		t.Fatal("projection identity or inactive state lost")
	}
	wire, _ := json.Marshal(first)
	for _, secret := range []string{key, "/source/cert.pem", "/source/key.pem"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatal("private server identity leaked")
		}
	}
	var enabled, grants, generations, deployments, audits int
	check(p.Pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM vpn_services WHERE node_id=$1::uuid AND enabled),
 (SELECT count(*) FROM vpn_effective_client_services WHERE tenant_id=$2::uuid),
 (SELECT count(*) FROM desired_states WHERE node_id=$1::uuid),
 (SELECT count(*) FROM deployments WHERE node_id=$1::uuid),
 (SELECT count(*) FROM audit_events WHERE node_id=$1::uuid AND event_type='xray_profile.prepared')`, node.ID, tenant.ID).Scan(&enabled, &grants, &generations, &deployments, &audits))
	if enabled != 0 || grants != 0 || generations != 0 || deployments != 0 || audits != 1 {
		t.Fatal("preparation activated access or replayed side effects")
	}
	if _, e = p.SetVPNServiceEnabledAndRebuild(ctx, first.Services[0].Service.ID, true); e == nil {
		t.Fatal("prepared service activated")
	}
	// An independently staged native service cannot be silently adopted.
	other, e := p.CreateNodeForRuntime(ctx, tenant.ID, "Already used node", security.HashToken("synthetic-prepare-other"), "xray")
	check(e)
	_, e = p.CreateVPNService(ctx, other.ID, "existing", "vless", "0.0.0.0", 9443, "tcp", "none", nil, nil)
	check(e)
	otherCert, e := p.CreateNodeCertificate(ctx, other.ID, "profile.example.test", "letsencrypt", "http-01", "production", nil, true)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_before=now()-interval '1 day',not_after=now()+interval '1 day' WHERE id=$1::uuid`, otherCert.ID)
	check(e)
	otherTLS := []XrayProfileTLSAssignment{{SourceInboundID: tls[0].SourceInboundID, CertificateID: otherCert.ID}}
	if _, e = p.PrepareXrayProfile(ctx, tenant.ID, imported.ID, other.ID, sourceNode, report.SHA256, otherTLS); !errors.Is(e, ErrXrayProfileHeld) {
		t.Fatal("used node adopted")
	}
	if _, e = prepare(otherTLS, report.SHA256); !errors.Is(e, ErrVPNServiceTLSInvalid) {
		t.Fatal("cross-node certificate accepted")
	}
	// A user-only new inventory revision can be reviewed without rewriting graph provenance.
	inv["captured_at"] = "2026-09-26T00:00:00Z"
	next, e := json.Marshal(inv)
	check(e)
	_, nextReport, e := remnawave.Parse(next)
	check(e)
	_, e = p.ApplyRemnawaveHeldDelta(ctx, imported.ID, tenant.ID, report.SHA256, nextReport.SHA256, next)
	check(e)
	again, e := prepare(tls, nextReport.SHA256)
	check(e)
	if again.InventorySHA256 != report.SHA256 || again.ReviewedSHA256 != nextReport.SHA256 || again.ProfileSHA256 != first.ProfileSHA256 {
		t.Fatal("graph provenance rewritten")
	}
	// Active inbound selection is part of the reviewed identity, even when raw config is identical.
	inv["nodes"].([]any)[0].(map[string]any)["configProfile"].(map[string]any)["activeInbounds"] = metadata
	inv["captured_at"] = "2026-09-26T00:00:01Z"
	changed, e := json.Marshal(inv)
	check(e)
	_, changedReport, e := remnawave.Parse(changed)
	check(e)
	_, e = p.ApplyRemnawaveHeldDelta(ctx, imported.ID, tenant.ID, nextReport.SHA256, changedReport.SHA256, changed)
	check(e)
	if _, e = prepare(tls, changedReport.SHA256); !errors.Is(e, ErrXrayProfileIdentity) {
		t.Fatal("source active selection changed without a new adoption review")
	}
}
