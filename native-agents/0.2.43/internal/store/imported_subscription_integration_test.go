//go:build integration

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"vpn-platform/internal/model"
	"vpn-platform/internal/subscriptioncompat"
)

// Synthetic active registry for read/lifecycle testing only. Actual owner
// preparation is independently tested against the held source projection.
func syntheticPublicSubscription(t *testing.T, ctx context.Context, p *Postgres, tenant, importID, digest string, services []model.ServiceSpec, profile *model.XrayProfileSpec, preparedOnly ...bool) string {
	t.Helper()
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	yes, no, limit := true, false, 2
	pageID, externalID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	policy := subscriptioncompat.Policy{Rules: subscriptioncompat.ResponseRules{Version: "1", Rules: []subscriptioncompat.ResponseRule{{Name: "fallback", Enabled: &yes, Operator: "AND", Response: "XRAY_BASE64", Conditions: []subscriptioncompat.ResponseCondition{}}}},
		Headers: map[string]string{"profile-title": "global", "profile-web-page-url": "{{SUBSCRIPTION_URL}}"},
		Remarks: map[string][]string{}, ShowRemarks: true, HWID: subscriptioncompat.HWIDPolicy{Enabled: &no, Fallback: &limit}, PageID: &pageID}
	for _, key := range []string{"HWIDMaxDevicesExceeded", "HWIDNotSupported", "disabledUsers", "emptyHosts", "expiredUsers", "limitedUsers"} {
		policy.Remarks[key] = []string{key}
	}
	external, err := policy.OverlayExternal(nil, map[string]string{"profile-title": "external"}, nil, nil, nil)
	check(err)
	bundle := ImportedSubscriptionBundle{Version: 1, Hosts: subscriptioncompat.Projection{InventorySHA256: digest, Hosts: []subscriptioncompat.BoundHost{}, Squads: []subscriptioncompat.SquadBinding{}},
		Policy: subscriptioncompat.PolicyProjection{InventorySHA256: digest, Global: policy, External: map[string]subscriptioncompat.Policy{externalID: external}, Pages: map[string]json.RawMessage{pageID: json.RawMessage(`{"synthetic":true}`)}}, Templates: map[string]subscriptioncompat.Template{}}
	bundle.Policy.PageDetails = map[string]subscriptioncompat.PageMetadata{pageID: {ID: pageID, Name: "Default", ViewPosition: 1}}
	for i, svc := range services {
		host := subscriptioncompat.Host{Name: fmt.Sprintf("Original source name %d", i), Address: "synthetic-profile.example.test", Port: svc.Port, Protocol: "vless", Transport: svc.Transport, Security: svc.Security, ProtocolOptions: subscriptioncompat.Options{"encryption": "none", "flow": ""}, TransportOptions: subscriptioncompat.Options{}, SecurityOptions: subscriptioncompat.Options{}}
		if svc.Protocol == "hysteria2" {
			host.Protocol = "hysteria"
			host.Transport = "hysteria"
			host.ProtocolOptions = subscriptioncompat.Options{"version": 2}
		}
		if svc.Reality != nil {
			host.SecurityOptions = subscriptioncompat.Options{"publicKey": profile.Bindings[i].RealityPublicKey, "serverName": svc.Reality.ServerName, "shortId": "", "fingerprint": "firefox"}
		} else {
			host.SecurityOptions = subscriptioncompat.Options{"serverName": svc.TLS.ServerName}
		}
		host.Metadata.Excluded = []string{}
		bundle.Hosts.Hosts = append(bundle.Hosts.Hosts, subscriptioncompat.BoundHost{SourceHostID: fmt.Sprintf("cccccccc-cccc-4ccc-8ccc-%012d", i+1), ServiceIDs: []string{svc.ID}, Host: host})
	}
	source := []byte(`{"synthetic_fixture":true}`)
	settingsSum := sha256.Sum256(source)
	settingsSHA := hex.EncodeToString(settingsSum[:])
	bundle.Policy.SettingsSHA256 = settingsSHA
	wire, err := json.Marshal(bundle)
	check(err)
	sum := sha256.Sum256(wire)
	_, err = p.Pool.Exec(ctx, `INSERT INTO remnawave_subscription_settings(import_id,settings_sha256,source) VALUES($1::uuid,$2,$3)`, importID, settingsSHA, source)
	check(err)
	var revision string
	check(p.Pool.QueryRow(ctx, `INSERT INTO imported_subscription_revisions(tenant_id,import_id,inventory_sha256,settings_sha256,bundle_sha256,bundle) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6) RETURNING id::text`, tenant, importID, digest, settingsSHA, hex.EncodeToString(sum[:]), wire).Scan(&revision))
	for _, host := range bundle.Hosts.Hosts {
		_, err = p.Pool.Exec(ctx, `INSERT INTO imported_subscription_host_services(revision_id,tenant_id,source_host_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)`, revision, tenant, host.SourceHostID, host.ServiceIDs[0])
		check(err)
	}
	_, err = p.Pool.Exec(ctx, `INSERT INTO imported_subscription_external_accounts(revision_id,tenant_id,legacy_id,source_external_id) VALUES($1::uuid,$2::uuid,1,$3::uuid)`, revision, tenant, externalID)
	check(err)
	_, err = p.Pool.Exec(ctx, `INSERT INTO imported_subscription_profiles(tenant_id,import_id,revision_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, tenant, importID, revision)
	check(err)
	var alias string
	check(p.Pool.QueryRow(ctx, `SELECT alias FROM bot_subscription_aliases WHERE tenant_id=$1::uuid AND legacy_id=1 AND state='active'`, tenant).Scan(&alias))
	_, err = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: alias})
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("prepared public profile resolved")
	}
	if len(preparedOnly) > 0 && preparedOnly[0] {
		return alias
	}
	_, err = p.Pool.Exec(ctx, `UPDATE imported_subscription_profiles SET state='active',activation_sha256=$2,activated_at=now() WHERE tenant_id=$1::uuid`, tenant, strings.Repeat("e", 64))
	check(err)
	_, err = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: alias})
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("held account resolved under active public fixture")
	}
	return alias
}
