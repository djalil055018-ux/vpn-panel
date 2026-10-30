//go:build integration

package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/security"
)

// Real PostgreSQL transaction/owner preparation and native desired assembler.
// The public settings revision is synthetic; this does not prove physical node
// handoff, public routing or an external traffic cutover.
func TestRemnawaveRuntimeCutoverIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	tenant, e := p.CreateTenant(ctx, "Synthetic atomic cutover")
	check(e)
	frozen := time.Now().UTC().Add(-2 * time.Second).Truncate(time.Microsecond)
	captured := frozen.Add(time.Second)
	raw, e := os.ReadFile("../remnawave/testdata/inventory.json")
	check(e)
	var inv map[string]any
	check(json.Unmarshal(raw, &inv))
	inv["source_origin"] = "https://cutover-" + tenant.ID + ".example.test"
	inv["started_at"] = frozen
	inv["captured_at"] = captured
	users := inv["users"].([]any)
	limited := map[string]any{}
	for k, v := range users[0].(map[string]any) {
		limited[k] = v
	}
	limited["id"] = 4
	limited["username"] = "synthetic-limited"
	limited["shortUuid"] = "synthetic-source-subscription-4"
	limited["subscriptionUrl"] = "https://subscriptions.example.test/synthetic-source-subscription-4"
	limited["vlessUuid"] = "44444444-4444-4444-8444-444444444444"
	limited["trojanPassword"] = "synthetic-trojan-credential-4"
	limited["ssPassword"] = "synthetic-ss-credential-4"
	limited["status"] = "LIMITED"
	limited["trafficLimitBytes"] = 100
	limited["userTraffic"] = map[string]any{"usedTrafficBytes": 100, "lifetimeUsedTrafficBytes": 200}
	users = append(users, limited)
	for _, value := range users {
		u := value.(map[string]any)
		u["trafficLimitStrategy"] = "NO_RESET"
		u["activeInternalSquads"] = users[0].(map[string]any)["activeInternalSquads"]
	}
	inv["users"] = users
	inv["verification"].(map[string]any)["source_total"] = 4
	inv["verification"].(map[string]any)["unique_user_ids"] = 4
	sourceID, profileID, inboundID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1", "cccccccc-cccc-4ccc-8ccc-ccccccccccc1"
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	inbound := map[string]any{"tag": "raw", "protocol": "vless", "listen": "0.0.0.0", "port": 443, "settings": map[string]any{"clients": []any{}, "decryption": "none"}, "streamSettings": map[string]any{"network": "raw", "security": "reality", "realitySettings": map[string]any{"target": "synthetic.example.test:443", "serverNames": []string{"synthetic.example.test"}, "shortIds": []string{""}, "privateKey": key}}}
	meta := []any{map[string]any{"uuid": inboundID, "profileUuid": profileID, "tag": "raw", "type": "vless", "network": "raw", "security": "reality", "port": 443, "rawInbound": inbound}}
	inv["nodes"] = []any{map[string]any{"uuid": sourceID, "isDisabled": false, "activePluginUuid": nil, "proxyUrl": nil, "consumptionMultiplier": 1, "nodeConsumptionMultiplier": 1, "configProfile": map[string]any{"activeConfigProfileUuid": profileID, "activeInbounds": meta}}}
	inv["config_profiles"] = map[string]any{"configProfiles": []any{map[string]any{"uuid": profileID, "config": map[string]any{"inbounds": []any{inbound}, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}}, "inbounds": meta, "nodes": []any{map[string]any{"uuid": sourceID}}}}}
	raw, e = json.Marshal(inv)
	check(e)
	_, review, e := remnawave.Parse(raw)
	check(e)
	imported, _, e := p.StageRemnawaveInventory(ctx, tenant.ID, raw, review.SHA256)
	check(e)
	_, e = p.PrepareRemnawaveNoResetQuota(ctx, imported.ID, tenant.ID, review.SHA256)
	check(e)
	_, e = p.PrepareBotBridge(ctx, tenant.ID, imported.ID, review.SHA256)
	check(e)
	bootstrap := security.HashToken("synthetic-cutover-bootstrap")
	node, e := p.CreateNodeForRuntime(ctx, tenant.ID, "Synthetic cutover node", bootstrap, "xray")
	check(e)
	preparation, e := p.PrepareXrayProfile(ctx, tenant.ID, imported.ID, node.ID, sourceID, review.SHA256, nil)
	check(e)
	_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-cutover-agent"), "0.2.31", "ubuntu", "24.04", "amd64", "xray")
	check(e)
	release, e := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.9.9", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/cutover.zip", SHA256: strings.Repeat("b", 64), Channel: "testing"})
	check(e)
	check(p.ApproveCoreRelease(ctx, release.ID))
	var profileRaw []byte
	var profile model.XrayProfileSpec
	check(p.Pool.QueryRow(ctx, `SELECT profile FROM node_xray_profiles WHERE node_id=$1::uuid`, node.ID).Scan(&profileRaw))
	check(json.Unmarshal(profileRaw, &profile))
	alias := syntheticPublicSubscription(t, ctx, p, tenant.ID, imported.ID, review.SHA256, []model.ServiceSpec{preparation.Services[0].Service}, &profile, true)
	var revision, bundleSHA string
	check(p.Pool.QueryRow(ctx, `SELECT r.id::text,r.bundle_sha256 FROM imported_subscription_profiles h JOIN imported_subscription_revisions r ON r.id=h.revision_id WHERE h.tenant_id=$1::uuid`, tenant.ID).Scan(&revision, &bundleSHA))
	_, e = p.Pool.Exec(ctx, `INSERT INTO imported_subscription_squad_services(revision_id,tenant_id,source_squad_id,service_id) VALUES($1::uuid,$2::uuid,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',$3::uuid)`, revision, tenant.ID, preparation.Services[0].Service.ID)
	check(e)
	_, e = p.PrepareBotSquadPlans(ctx, tenant.ID, imported.ID, review.SHA256, revision, bundleSHA)
	check(e)
	request := RemnawaveCutoverRequest{TenantID: tenant.ID, InventorySHA256: review.SHA256, SubscriptionRevisionID: revision, BundleSHA256: bundleSHA, CoreReleaseID: release.ID, SourceFreezeSHA256: strings.Repeat("c", 64), SourceFrozenAt: frozen, RollbackDeadline: time.Now().UTC().Add(10 * time.Minute), Nodes: []RemnawaveNodeHandoff{{NodeID: node.ID, MaterialSHA256: strings.Repeat("d", 64), HandoffSHA256: strings.Repeat("e", 64), SourceStopped: true, SourceRestartFenced: true, MaterialPublished: true, RollbackArmed: true}}}
	snapshot := func() string {
		var s string
		check(p.Pool.QueryRow(ctx, `SELECT jsonb_build_object('held',(SELECT count(*) FROM vpn_clients WHERE tenant_id=$1::uuid AND remnawave_hold),'generations',(SELECT count(*) FROM desired_states WHERE node_id=$2::uuid),'enabled',(SELECT count(*) FROM vpn_services WHERE node_id=$2::uuid AND enabled),'profile',(SELECT state FROM node_xray_profiles WHERE node_id=$2::uuid),'bot',(SELECT state FROM bot_profiles WHERE tenant_id=$1::uuid),'cutovers',(SELECT count(*) FROM remnawave_cutovers WHERE import_id=$3::uuid))::text`, tenant.ID, node.ID, imported.ID).Scan(&s))
		return s
	}
	before := snapshot()
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant.ID, Role: "operator"})
	if _, e = p.BeginRemnawaveRuntimeCutover(operator, imported.ID, request); !errors.Is(e, ErrNotFound) {
		t.Fatal("tenant operator activated an owner cutover")
	}
	invalid := request
	invalid.Nodes = append([]RemnawaveNodeHandoff{}, request.Nodes...)
	invalid.Nodes[0].SourceStopped = false
	if _, e = p.BeginRemnawaveRuntimeCutover(ctx, imported.ID, invalid); e == nil {
		t.Fatal("unfenced source activated")
	}
	invalid = request
	invalid.InventorySHA256 = strings.Repeat("0", 64)
	if _, e = p.BeginRemnawaveRuntimeCutover(ctx, imported.ID, invalid); e == nil {
		t.Fatal("unreviewed source activated")
	}
	if snapshot() != before {
		t.Fatal("rejected activation changed held state")
	}
	// A failure after hold release and service activation must roll the entire
	// transaction back, including first desired generation and cutover receipt.
	_, e = p.Pool.Exec(ctx, `CREATE FUNCTION synthetic_cutover_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic late failure'; END; $$; CREATE TRIGGER synthetic_cutover_failure BEFORE INSERT ON desired_states FOR EACH ROW EXECUTE FUNCTION synthetic_cutover_failure();`)
	check(e)
	if _, e = p.BeginRemnawaveRuntimeCutover(ctx, imported.ID, request); e == nil || !strings.Contains(e.Error(), "synthetic late failure") {
		t.Fatalf("late failure not reached: %v", e)
	}
	if snapshot() != before {
		t.Fatal("late failure leaked a partial cutover")
	}
	_, e = p.Pool.Exec(ctx, `DROP TRIGGER synthetic_cutover_failure ON desired_states;DROP FUNCTION synthetic_cutover_failure()`)
	check(e)
	const calls = 4
	results := make(chan RemnawaveCutoverResult, calls)
	failures := make(chan error, calls)
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := p.BeginRemnawaveRuntimeCutover(ctx, imported.ID, request)
			results <- out
			failures <- err
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		check(err)
	}
	var first RemnawaveCutoverResult
	for result := range results {
		if first.ImportID == "" {
			first = result
		} else if !reflect.DeepEqual(first, result) {
			t.Fatal("retry changed cutover identity")
		}
	}
	if first.State != "verifying" || first.Clients != 4 || first.Deleted != 0 || first.BotActive || first.PublicSubscriptionsActive || first.PhysicalProof != "owner_attestation" {
		t.Fatal("incorrect publication state")
	}
	desired, exists, e := p.LatestDesiredState(ctx, node.ID)
	check(e)
	if !exists || desired.Generation != 1 || desired.XrayProfile == nil || len(desired.Services) != 1 || len(desired.Services[0].Clients) != 1 {
		t.Fatal("first generation omitted source profile or lost access eligibility")
	}
	var count int
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM desired_states WHERE node_id=$1::uuid`, node.ID).Scan(&count))
	if count != 1 {
		t.Fatal("retry published extra generations")
	}
	_, e = p.BotUser(operator, 1, nil)
	if !errors.Is(e, ErrBotBridgeHeld) {
		t.Fatal("bot management exposed before verification")
	}
	_, e = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: alias})
	if !errors.Is(e, ErrNotFound) {
		t.Fatal("public subscriptions exposed before verification")
	}
	_, e = p.ApplyRemnawaveHeldDelta(ctx, imported.ID, tenant.ID, review.SHA256, review.SHA256, raw)
	if e == nil {
		t.Fatal("held refresh rewrote an activating import")
	}
	// Publication tests use synthetic health and owner attestations. They prove
	// database gates/atomicity, not a physical handoff or external traffic.
	publication := RemnawavePublicationRequest{TenantID: tenant.ID, RuntimeRequestSHA256: first.RequestSHA256,
		VerifiedAt: time.Now().UTC(), Nodes: []RemnawavePublicationNode{{NodeID: node.ID,
			Generation: desired.Generation, ProfileSHA256: desired.XrayProfile.SHA256,
			ServiceIDs: []string{desired.Services[0].ID}, ExternalProofSHA256: strings.Repeat("a", 64),
			GuardCommitSHA256: strings.Repeat("f", 64), GuardCommittedAt: time.Now().UTC().Add(-time.Millisecond), SourceStillFenced: true}}}
	publication.Nodes[0].GuardCommittedAt = publication.VerifiedAt
	pubSnapshot := func() string {
		var s string
		check(p.Pool.QueryRow(ctx, `SELECT jsonb_build_object('bot',(SELECT state FROM bot_profiles WHERE tenant_id=$1::uuid),'public',(SELECT state FROM imported_subscription_profiles WHERE tenant_id=$1::uuid),'cutover',(SELECT state FROM remnawave_cutovers WHERE import_id=$2::uuid),'import',(SELECT state FROM remnawave_imports WHERE id=$2::uuid),'audits',(SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND event_type='remnawave.publication_committed'),'generations',(SELECT count(*) FROM desired_states WHERE node_id=$3::uuid))::text`, tenant.ID, imported.ID, node.ID).Scan(&s))
		return s
	}
	beforePublication := pubSnapshot()
	if _, e = p.PublishRemnawaveCutover(ctx, imported.ID, publication); !errors.Is(e, ErrRemnawaveCutover) {
		t.Fatalf("unconverged node accepted or unexpected error: %v", e)
	}
	if pubSnapshot() != beforePublication {
		t.Fatal("unconverged publication changed state")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE nodes SET status='online',last_seen_at=now(),applied_generation=desired_generation WHERE id=$1::uuid`, node.ID)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE deployments SET status='healthy',completed_at=now(),applied_core_version=$2 WHERE node_id=$1::uuid`, node.ID, release.Version)
	check(e)
	_, e = p.Pool.Exec(ctx, `INSERT INTO node_health(node_id,healthy,applied_generation,core,core_version,message,checked_at) VALUES($1::uuid,true,1,'xray',$2,'synthetic publication fixture',clock_timestamp()) ON CONFLICT(node_id) DO UPDATE SET healthy=true,applied_generation=1,core='xray',core_version=excluded.core_version,checked_at=excluded.checked_at`, node.ID, release.Version)
	check(e)
	publication.VerifiedAt = time.Now().UTC()
	if _, e = p.PublishRemnawaveCutover(operator, imported.ID, publication); !errors.Is(e, ErrNotFound) {
		t.Fatal("operator published cutover")
	}
	for _, test := range []struct {
		name   string
		change func(*RemnawavePublicationRequest)
	}{
		{"unfenced", func(q *RemnawavePublicationRequest) { q.Nodes[0].SourceStillFenced = false }},
		{"missing-service", func(q *RemnawavePublicationRequest) { q.Nodes[0].ServiceIDs = []string{} }},
		{"wrong-generation", func(q *RemnawavePublicationRequest) { q.Nodes[0].Generation++ }},
		{"wrong-profile", func(q *RemnawavePublicationRequest) { q.Nodes[0].ProfileSHA256 = strings.Repeat("0", 64) }},
		{"wrong-runtime", func(q *RemnawavePublicationRequest) { q.RuntimeRequestSHA256 = strings.Repeat("0", 64) }},
		{"stale-proof", func(q *RemnawavePublicationRequest) { q.VerifiedAt = time.Now().UTC().Add(-6 * time.Minute) }},
		{"future-proof", func(q *RemnawavePublicationRequest) { q.VerifiedAt = time.Now().UTC().Add(time.Minute) }},
		{"pre-cutover-guard", func(q *RemnawavePublicationRequest) { q.Nodes[0].GuardCommittedAt = frozen }},
		{"late-guard", func(q *RemnawavePublicationRequest) { q.Nodes[0].GuardCommittedAt = request.RollbackDeadline }},
	} {
		q := publication
		q.Nodes = append([]RemnawavePublicationNode{}, publication.Nodes...)
		test.change(&q)
		if _, e = p.PublishRemnawaveCutover(ctx, imported.ID, q); !errors.Is(e, ErrRemnawaveCutover) {
			t.Fatalf("%s accepted or unexpected error: %v", test.name, e)
		}
		if pubSnapshot() != beforePublication {
			t.Fatalf("%s leaked changes", test.name)
		}
	}
	// Fail after bot activation: all public/profile/receipt state must roll back.
	_, e = p.Pool.Exec(ctx, `CREATE FUNCTION synthetic_publication_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic publication late failure'; END; $$; CREATE TRIGGER synthetic_publication_failure BEFORE UPDATE ON imported_subscription_profiles FOR EACH ROW EXECUTE FUNCTION synthetic_publication_failure();`)
	check(e)
	if _, e = p.PublishRemnawaveCutover(ctx, imported.ID, publication); e == nil || !strings.Contains(e.Error(), "synthetic publication late failure") {
		t.Fatalf("publication late failure not reached: %v", e)
	}
	if pubSnapshot() != beforePublication {
		t.Fatal("late failure exposed partial publication")
	}
	_, e = p.Pool.Exec(ctx, `DROP TRIGGER synthetic_publication_failure ON imported_subscription_profiles;DROP FUNCTION synthetic_publication_failure()`)
	check(e)
	pubResults := make(chan RemnawavePublicationResult, calls)
	pubErrors := make(chan error, calls)
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := p.PublishRemnawaveCutover(ctx, imported.ID, publication)
			pubResults <- r
			pubErrors <- e
		}()
	}
	wg.Wait()
	close(pubResults)
	close(pubErrors)
	for e := range pubErrors {
		check(e)
	}
	var published RemnawavePublicationResult
	for r := range pubResults {
		if published.ImportID == "" {
			published = r
		} else if r != published {
			t.Fatal("publication retry changed receipt")
		}
	}
	if published.State != "active" || published.PhysicalProof != "owner_attestation" || published.PublicationSHA256 == "" {
		t.Fatal("incorrect publication receipt")
	}
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1::uuid AND event_type='remnawave.publication_committed'`, tenant.ID).Scan(&count))
	if count != 1 {
		t.Fatal("publication repeated its side effects")
	}
	status, e := p.BotBridgeStatus(operator)
	check(e)
	expectedCaps := []string{"numeric_identity_v1", "users_v1", "no_reset_quota_v1", "squad_grants_v1", "subscription_v1", "devices_v1", "nodes_v1", "durable_operations_v1", "customer_state_v1"}
	if !status.MigrationReady || status.State != "active" || !reflect.DeepEqual(status.Capabilities, expectedCaps) {
		t.Fatal("committed bridge not ready for existing adapter")
	}
	_, e = p.BotUser(operator, 1, nil)
	check(e)
	_, e = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: alias})
	check(e)
	check(p.Pool.QueryRow(ctx, `SELECT count(*) FROM desired_states WHERE node_id=$1::uuid`, node.ID).Scan(&count))
	if count != 1 {
		t.Fatal("publication created extra generation")
	}
	// A later outage must not disable bot management. An explicit pause must.
	_, e = p.Pool.Exec(ctx, `UPDATE nodes SET status='offline',last_seen_at=now()-interval '2 minutes' WHERE id=$1::uuid`, node.ID)
	check(e)
	status, e = p.BotBridgeStatus(operator)
	check(e)
	if !status.MigrationReady {
		t.Fatal("node outage disabled management")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant.ID)
	check(e)
	_, e = p.PublishRemnawaveCutover(ctx, imported.ID, publication)
	check(e)
	status, e = p.BotBridgeStatus(operator)
	check(e)
	if status.State != "paused" || status.MigrationReady {
		t.Fatal("exact replay resumed independently paused bot")
	}
	q := publication
	q.VerifiedAt = q.VerifiedAt.Add(time.Microsecond)
	if _, e = p.PublishRemnawaveCutover(ctx, imported.ID, q); !errors.Is(e, ErrRemnawaveCutover) {
		t.Fatal("changed proof replaced committed receipt")
	}
}
