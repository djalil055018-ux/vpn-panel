package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/xrayprofile"
)

func validateCutoverNodesTx(ctx context.Context, tx pgx.Tx, req RemnawaveCutoverRequest, importID string, raw []byte) error {
	var inventory struct {
		Nodes []struct {
			ID       string `json:"uuid"`
			Disabled bool   `json:"isDisabled"`
		} `json:"nodes"`
	}
	if json.Unmarshal(raw, &inventory) != nil {
		return ErrRemnawaveCutover
	}
	expectedSources := map[string]bool{}
	for _, n := range inventory.Nodes {
		if !n.Disabled {
			if !xrayPreparationUUID.MatchString(strings.ToLower(n.ID)) || expectedSources[strings.ToLower(n.ID)] {
				return ErrRemnawaveCutover
			}
			expectedSources[strings.ToLower(n.ID)] = true
		}
	}
	if len(expectedSources) != len(req.Nodes) {
		return ErrRemnawaveCutover
	}
	expected := map[string]RemnawaveNodeHandoff{}
	for _, n := range req.Nodes {
		expected[n.NodeID] = n
	}
	var registeredCount int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_xray_profiles WHERE import_id=$1::uuid AND tenant_id=$2::uuid`, importID, req.TenantID).Scan(&registeredCount); err != nil {
		return err
	}
	if registeredCount != len(req.Nodes) {
		return ErrRemnawaveCutover
	}
	// Preserve preparation's certificate-before-node lock order.
	rows, err := tx.Query(ctx, `SELECT c.id::text,c.node_id::text,t.source_node_id::text,t.adoption_sha256,
 c.domain=t.domain AND c.fingerprint_sha256=t.fingerprint_sha256 AND c.environment='production'
 AND c.status IN ('active','renewing') AND c.not_before<=now() AND c.not_after>now()
 FROM node_certificates c JOIN imported_tls_certificates t ON t.certificate_id=c.id AND t.node_id=c.node_id AND t.tenant_id=c.tenant_id
 WHERE t.import_id=$1::uuid AND t.tenant_id=$2::uuid ORDER BY c.id FOR SHARE OF c,t`, importID, req.TenantID)
	if err != nil {
		return err
	}
	certSources := map[string]string{}
	for rows.Next() {
		var id, node, source, digest string
		var valid bool
		if err = rows.Scan(&id, &node, &source, &digest, &valid); err != nil {
			rows.Close()
			return err
		}
		if !valid || expected[node].MaterialSHA256 != digest {
			rows.Close()
			return ErrImportedTLS
		}
		certSources[id] = source
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, node := range req.Nodes {
		var generation, applied int64
		var runtime, agent, osName, arch, status string
		var registered, recent bool
		err = tx.QueryRow(ctx, `SELECT desired_generation,applied_generation,runtime_core,COALESCE(agent_version,''),COALESCE(os_name,''),COALESCE(architecture,''),status,agent_token_hash IS NOT NULL,COALESCE(last_seen_at>now()-interval '90 seconds',false)
   FROM nodes WHERE id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, node.NodeID, req.TenantID).Scan(&generation, &applied, &runtime, &agent, &osName, &arch, &status, &registered, &recent)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		validOS := map[string]bool{"ubuntu": true, "debian": true, "alpine": true, "centos": true, "rhel": true, "fedora": true, "rocky": true, "almalinux": true, "linux": true}
		if generation != 0 || applied != 0 || runtime != "xray" || !xrayprofile.AgentCompatible(agent) || !registered || !recent || status != "online" || arch != "amd64" || !validOS[strings.ToLower(osName)] {
			return ErrXrayProfileHeld
		}
		var sourceID, profileID, profileSHA, profileState string
		var profileRaw []byte
		err = tx.QueryRow(ctx, `SELECT source_node_id::text,source_profile_id::text,profile_sha256,state,profile FROM node_xray_profiles WHERE node_id=$1::uuid AND tenant_id=$2::uuid AND import_id=$3::uuid FOR UPDATE`, node.NodeID, req.TenantID, importID).Scan(&sourceID, &profileID, &profileSHA, &profileState, &profileRaw)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrXrayProfileHeld
		}
		if err != nil {
			return err
		}
		if !expectedSources[sourceID] || profileState != "prepared" {
			return ErrXrayProfileHeld
		}
		delete(expectedSources, sourceID)
		var history bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM desired_states WHERE node_id=$1::uuid) OR EXISTS(SELECT 1 FROM deployments WHERE node_id=$1::uuid) OR EXISTS(SELECT 1 FROM node_client_traffic_cursors WHERE node_id=$1::uuid)`, node.NodeID).Scan(&history)
		if err != nil {
			return err
		}
		if history {
			return ErrXrayProfileHeld
		}
		var profile model.XrayProfileSpec
		if json.Unmarshal(profileRaw, &profile) != nil || profile.SHA256 != profileSHA || xrayprofile.Validate(&profile) != nil {
			return ErrXrayProfileIdentity
		}
		rows, err = tx.Query(ctx, `SELECT b.source_inbound_id::text,b.inbound_tag,b.source_enabled,b.service_spec,s.enabled
   FROM node_xray_profile_bindings b JOIN vpn_services s ON s.id=b.service_id AND s.node_id=b.node_id AND s.tenant_id=b.tenant_id
   WHERE b.node_id=$1::uuid ORDER BY b.service_id FOR UPDATE OF s`, node.NodeID)
		if err != nil {
			return err
		}
		bindings := map[string]xrayprofile.SourceService{}
		assignments := []xrayprofile.SourceServiceAssignment{}
		for rows.Next() {
			var binding xrayprofile.SourceService
			var wire []byte
			var enabled bool
			if err = rows.Scan(&binding.InboundID, &binding.InboundTag, &binding.Enabled, &wire, &enabled); err != nil {
				rows.Close()
				return err
			}
			if enabled || json.Unmarshal(wire, &binding.Service) != nil {
				rows.Close()
				return ErrXrayProfileIdentity
			}
			if binding.Service.TLS != nil && certSources[binding.Service.TLS.CertificateID] != sourceID {
				rows.Close()
				return ErrImportedTLS
			}
			bindings[binding.InboundID] = binding
			assignments = append(assignments, xrayprofile.SourceServiceAssignment{InboundID: binding.InboundID, ServiceID: binding.Service.ID, TLS: binding.Service.TLS})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		fresh, e := xrayprofile.ProjectSourceNode(raw, sourceID, assignments)
		if e != nil || fresh.ProfileID != profileID || fresh.Profile.SHA256 != profileSHA || len(fresh.Services) != len(bindings) {
			return ErrXrayProfileIdentity
		}
		for _, binding := range fresh.Services {
			if !reflect.DeepEqual(binding, bindings[binding.InboundID]) {
				return ErrXrayProfileIdentity
			}
		}
		var serviceCount int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM vpn_services WHERE node_id=$1::uuid`, node.NodeID).Scan(&serviceCount); err != nil {
			return err
		}
		if serviceCount != len(fresh.Services) {
			return ErrXrayProfileIdentity
		}
	}
	return nil
}

func validateCutoverAccountsTx(ctx context.Context, tx pgx.Tx, req RemnawaveCutoverRequest, importID string, inv remnawave.Inventory, raw []byte) (int, int, error) {
	metadata, err := botbridge.ParseMetadata(raw)
	if err != nil {
		return 0, 0, err
	}
	byID := map[int64]botbridge.UserMetadata{}
	for _, u := range metadata.Users {
		byID[u.ID] = u
	}
	var sourceCount int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM remnawave_import_clients WHERE import_id=$1::uuid AND source_present`, importID).Scan(&sourceCount); err != nil {
		return 0, 0, err
	}
	if sourceCount != len(inv.Users) {
		return 0, 0, ErrRemnawaveConflict
	}
	// No hidden independent grants or pre-existing native counters may be mixed
	// into the first imported runtime. Nothing is erased to make this test pass.
	var changed bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remnawave_import_clients m JOIN vpn_clients c ON c.id=m.client_id WHERE m.import_id=$1::uuid AND (
  EXISTS(SELECT 1 FROM node_client_traffic_cursors x WHERE x.client_id=c.id) OR
  EXISTS(SELECT 1 FROM vpn_client_services x WHERE x.client_id=c.id) OR
  EXISTS(SELECT 1 FROM vpn_client_access_plans x WHERE x.client_id=c.id) OR
  EXISTS(SELECT 1 FROM billing_entitlements x WHERE x.client_id=c.id)))`, importID).Scan(&changed)
	if err != nil {
		return 0, 0, err
	}
	if changed {
		return 0, 0, ErrRemnawaveCutover
	}
	clients, deleted := 0, 0
	for _, u := range inv.Users {
		if u.TrafficLimitStrategy != "NO_RESET" || (u.Status == "LIMITED" && (*u.TrafficLimitBytes == 0 || *u.Traffic.Used < *u.TrafficLimitBytes)) || (u.Status == "EXPIRED" && u.ExpireAt.After(inv.CapturedAt)) {
			return 0, 0, ErrRemnawaveCutover
		}
		var clientID *string
		var tombstone bool
		var sourceStatus string
		err = tx.QueryRow(ctx, `SELECT client_id::text,deleted_at IS NOT NULL AND deleted_client_id IS NOT NULL,source_status FROM remnawave_import_clients WHERE import_id=$1::uuid AND source_user_id=$2 AND source_present FOR UPDATE`, importID, u.ID).Scan(&clientID, &tombstone, &sourceStatus)
		if err != nil {
			return 0, 0, err
		}
		if clientID == nil && tombstone {
			deleted++
			continue
		}
		if clientID == nil || tombstone || sourceStatus != u.Status {
			return 0, 0, ErrRemnawaveConflict
		}
		meta, ok := byID[u.ID]
		if !ok {
			return 0, 0, ErrRemnawaveConflict
		}
		var valid bool
		err = tx.QueryRow(ctx, `SELECT c.tenant_id=$2::uuid AND c.remnawave_hold AND c.status='disabled' AND c.vless_uuid::text=$3 AND c.expires_at=$4
   AND q.limit_bytes=$5 AND q.baseline_bytes=$6 AND q.baseline_at=$7 AND q.uplink_bytes=0 AND q.downlink_bytes=0
   FROM vpn_clients c JOIN vpn_client_continuous_quotas q ON q.client_id=c.id WHERE c.id=$1::uuid FOR UPDATE OF c,q`, *clientID, req.TenantID, strings.ToLower(u.VLESSUUID), u.ExpireAt.Truncate(time.Microsecond), *u.TrafficLimitBytes, *u.Traffic.Used, inv.CapturedAt.Truncate(time.Microsecond)).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrRemnawaveCutover
		}
		if err != nil {
			return 0, 0, err
		}
		if !valid {
			return 0, 0, ErrRemnawaveConflict
		}
		err = tx.QueryRow(ctx, `SELECT client_id=$3::uuid AND source_present AND deleted_at IS NULL AND username=$4 AND telegram_id IS NOT DISTINCT FROM $5::bigint
   AND email IS NOT DISTINCT FROM $6::text AND description IS NOT DISTINCT FROM $7::text AND hwid_device_limit IS NOT DISTINCT FROM $8::integer
   AND lifetime_offset_bytes=$9 AND source_created_at=$10
   AND EXISTS(SELECT 1 FROM bot_subscription_aliases a WHERE a.tenant_id=$1::uuid AND a.legacy_id=$2 AND a.alias=$11 AND a.state='active')
   FROM bot_accounts WHERE tenant_id=$1::uuid AND legacy_id=$2 FOR UPDATE`, req.TenantID, u.ID, *clientID, meta.Username, meta.TelegramID, meta.Email, meta.Description, meta.HWIDDeviceLimit, meta.LifetimeBytes, meta.CreatedAt.Truncate(time.Microsecond), meta.ShortUUID).Scan(&valid)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrRemnawaveConflict
		}
		if err != nil {
			return 0, 0, err
		}
		if !valid {
			return 0, 0, ErrRemnawaveConflict
		}
		var squads []string
		if err = tx.QueryRow(ctx, `SELECT COALESCE(array_agg(source_uuid::text ORDER BY source_uuid),ARRAY[]::text[]) FROM bot_account_squads WHERE tenant_id=$1::uuid AND legacy_id=$2`, req.TenantID, u.ID).Scan(&squads); err != nil {
			return 0, 0, err
		}
		wanted := append([]string{}, meta.SquadIDs...)
		sort.Strings(wanted)
		if !reflect.DeepEqual(squads, wanted) {
			return 0, 0, ErrRemnawaveConflict
		}
		clients++
	}
	var accounts int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM bot_accounts WHERE tenant_id=$1::uuid AND source_present AND deleted_at IS NULL`, req.TenantID).Scan(&accounts); err != nil {
		return 0, 0, err
	}
	if accounts != clients {
		return 0, 0, ErrRemnawaveConflict
	}
	return clients, deleted, nil
}

func validateCutoverPlansTx(ctx context.Context, tx pgx.Tx, req RemnawaveCutoverRequest, raw []byte) error {
	metadata, err := botbridge.ParseMetadata(raw)
	if err != nil {
		return err
	}
	expected := map[string]string{}
	for _, s := range metadata.Squads {
		expected[s.UUID] = s.Name
	}
	rows, err := tx.Query(ctx, `SELECT s.source_uuid::text,s.name,s.plan_id::text,p.name,p.code,p.enabled
  FROM bot_squads s LEFT JOIN vpn_access_plans p ON p.id=s.plan_id AND p.tenant_id=s.tenant_id
  WHERE s.tenant_id=$1::uuid AND s.source_present ORDER BY s.source_uuid FOR UPDATE OF s`, req.TenantID)
	if err != nil {
		return err
	}
	type plan struct{ source, name, id string }
	plans := []plan{}
	for rows.Next() {
		var source, name string
		var id, planName, code *string
		var enabled *bool
		if err = rows.Scan(&source, &name, &id, &planName, &code, &enabled); err != nil {
			rows.Close()
			return err
		}
		if expected[source] != name || id == nil || planName == nil || code == nil || enabled == nil || *enabled || *planName != "Remnawave: "+name || *code != "remna-"+strings.ReplaceAll(source, "-", "") {
			rows.Close()
			return ErrBotBridgeConflict
		}
		plans = append(plans, plan{source: source, name: name, id: *id})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(plans) != len(expected) {
		return ErrBotBridgeConflict
	}
	for _, p := range plans {
		if _, err = tx.Exec(ctx, `SELECT id FROM vpn_access_plans WHERE id=$1::uuid FOR UPDATE`, p.id); err != nil {
			return err
		}
		var clean bool
		err = tx.QueryRow(ctx, `SELECT NOT EXISTS(
   (SELECT service_id FROM vpn_access_plan_services WHERE plan_id=$1::uuid AND tenant_id=$2::uuid
    EXCEPT SELECT service_id FROM imported_subscription_squad_services WHERE revision_id=$3::uuid AND source_squad_id=$4::uuid AND tenant_id=$2::uuid)
   UNION ALL
   (SELECT service_id FROM imported_subscription_squad_services WHERE revision_id=$3::uuid AND source_squad_id=$4::uuid AND tenant_id=$2::uuid
    EXCEPT SELECT service_id FROM vpn_access_plan_services WHERE plan_id=$1::uuid AND tenant_id=$2::uuid))
   AND NOT EXISTS(SELECT 1 FROM vpn_client_access_plans WHERE plan_id=$1::uuid)
   AND NOT EXISTS(SELECT 1 FROM billing_entitlements WHERE plan_id=$1::uuid)
   AND NOT EXISTS(SELECT 1 FROM billing_offers WHERE plan_id=$1::uuid)
   AND NOT EXISTS(SELECT 1 FROM billing_invoices WHERE plan_id=$1::uuid)`, p.id, req.TenantID, req.SubscriptionRevisionID, p.source).Scan(&clean)
		if err != nil {
			return err
		}
		if !clean {
			return ErrBotBridgeConflict
		}
	}
	return nil
}
