//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/xrayprofile"
)

// Synthetic activated registry only. This exercises the initial transaction's
// assembler; it is not an owner-facing physical adoption/activation workflow.
func TestXrayProfileInitialDesiredIntegration(t *testing.T) {
	ctx, p, tenant, importID, digest := botFixture(t)
	check := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	bootstrap := security.HashToken("synthetic-initial-xray-bootstrap")
	node, e := p.CreateNodeForRuntime(ctx, tenant, "Initial imported runtime", bootstrap, "xray")
	check(e)
	_, e = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-initial-xray-agent"), "0.2.31", "ubuntu", "24.04", "amd64", "xray")
	check(e)
	release, e := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.9.9", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/initial-profile.zip", SHA256: strings.Repeat("a", 64), Channel: "testing"})
	check(e)
	check(p.ApproveCoreRelease(ctx, release.ID))
	core := model.CoreRelease{Type: release.Type, Version: release.Version, SHA256: release.SHA256, DownloadURL: release.DownloadURL, Channel: release.Channel}
	var serviceID string
	check(p.Pool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&serviceID))
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	raw := []byte(`{"inbounds":[{"tag":"raw","protocol":"vless","listen":"0.0.0.0","port":443,"settings":{"clients":[],"decryption":"none"},"streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"profile.example.test:443","serverNames":["profile.example.test"],"shortIds":[""],"privateKey":"` + key + `"}}}],"outbounds":[{"tag":"DIRECT","protocol":"freedom"}]}`)
	profile, _, e := xrayprofile.Project(raw, []model.XrayProfileBinding{{ServiceID: serviceID, InboundTag: "raw"}})
	check(e)
	svc := model.ServiceSpec{ID: serviceID, Protocol: "vless", Listen: "0.0.0.0", Port: 443, Transport: "tcp", Security: "reality", Reality: &model.RealitySpec{Destination: "profile.example.test:443", ServerName: "profile.example.test", Fingerprint: "chrome", ShortID: "", SecretRef: "reality/" + serviceID}}
	tx, e := p.Pool.Begin(ctx)
	check(e)
	defer tx.Rollback(context.WithoutCancel(ctx))
	check(lockTenantAccess(ctx, tx, tenant))
	wire, e := json.Marshal(profile)
	check(e)
	_, e = tx.Exec(ctx, `INSERT INTO node_xray_profiles(node_id,tenant_id,import_id,inventory_sha256,source_node_id,source_profile_id,profile_sha256,profile,state,adoption_sha256,activated_at) VALUES($1::uuid,$2::uuid,$3::uuid,$4,gen_random_uuid(),gen_random_uuid(),$5,$6::jsonb,'active',$7,now())`, node.ID, tenant, importID, digest, profile.SHA256, string(wire), strings.Repeat("e", 64))
	check(e)
	spec, e := json.Marshal(svc)
	check(e)
	_, e = tx.Exec(ctx, `INSERT INTO node_xray_profile_bindings(node_id,tenant_id,service_id,source_inbound_id,source_enabled,inbound_tag,service_spec) VALUES($1::uuid,$2::uuid,$3::uuid,gen_random_uuid(),true,'raw',$4::jsonb)`, node.ID, tenant, serviceID, string(spec))
	check(e)
	_, e = tx.Exec(ctx, `INSERT INTO vpn_services(id,tenant_id,node_id,name,protocol,listen,port,transport,security,enabled) VALUES($1::uuid,$2::uuid,$3::uuid,'raw','vless','0.0.0.0',443,'tcp','reality',true)`, serviceID, tenant, node.ID)
	check(e)
	_, e = tx.Exec(ctx, `INSERT INTO vpn_service_reality(service_id,tenant_id,destination,server_name,fingerprint,short_id,secret_ref,public_key) VALUES($1::uuid,$2::uuid,$3,$4,$5,'',$6,$7)`, serviceID, tenant, svc.Reality.Destination, svc.Reality.ServerName, svc.Reality.Fingerprint, svc.Reality.SecretRef, profile.Bindings[0].RealityPublicKey)
	check(e)
	var current int64
	check(tx.QueryRow(ctx, `SELECT desired_generation FROM nodes WHERE id=$1::uuid FOR UPDATE`, node.ID).Scan(&current))
	if current != 0 {
		t.Fatal("fixture has an existing desired state")
	}
	_, _, e = buildNodeDesiredStateTx(ctx, tx, node.ID)
	if !errors.Is(e, ErrNotFound) {
		t.Fatal("ordinary rebuild accepted uninitialized node")
	}
	initial, used, e := buildNodeDesiredWithBaseTx(ctx, tx, node.ID, 0, model.DesiredState{Core: core}, release.ID)
	check(e)
	if initial.Generation != 1 || used != release.ID || initial.XrayProfile == nil || initial.XrayProfile.SHA256 != profile.SHA256 || len(initial.Services) != 1 || len(initial.Services[0].Clients) != 0 {
		t.Fatal("initial profile or held-account exclusion failed")
	}
	// Populate direct native grants for all three source accounts, but only the
	// first is eligible. Held, disabled and expired accounts must not leak access.
	_, e = tx.Exec(ctx, `INSERT INTO vpn_client_services(tenant_id,client_id,service_id) SELECT $1::uuid,c.id,$2::uuid FROM vpn_clients c WHERE c.tenant_id=$1::uuid`, tenant, serviceID)
	check(e)
	_, e = tx.Exec(ctx, `UPDATE vpn_clients c SET remnawave_hold=false,status='active',expires_at=CASE WHEN m.source_user_id=1 THEN now()+interval '1 day' ELSE now()-interval '1 day' END FROM remnawave_import_clients m WHERE m.client_id=c.id AND m.import_id=$1::uuid AND m.source_user_id IN (1,2)`, importID)
	check(e)
	initial, used, e = buildNodeDesiredWithBaseTx(ctx, tx, node.ID, 0, model.DesiredState{Core: core}, release.ID)
	check(e)
	if len(initial.Services[0].Clients) != 1 {
		t.Fatal("initial account eligibility differs from native rebuild")
	}
	corrupt := *profile
	corrupt.SHA256 = strings.Repeat("0", 64)
	_, _, e = buildNodeDesiredWithBaseTx(ctx, tx, node.ID, 0, model.DesiredState{Core: core, XrayProfile: &corrupt}, release.ID)
	if !errors.Is(e, ErrXrayProfileIdentity) {
		t.Fatal("initial seed dropped registered profile identity")
	}
	check(saveDesiredStateTx(ctx, tx, node.ID, initial, used))
	check(tx.Commit(ctx))
	mutation, e := p.RebuildNodeDesiredState(ctx, node.ID)
	check(e)
	_ = mutation
	state, exists, e := p.LatestDesiredState(ctx, node.ID)
	check(e)
	if !exists || state.Generation != 2 || !reflect.DeepEqual(state.Services, initial.Services) || !reflect.DeepEqual(state.XrayProfile, initial.XrayProfile) {
		t.Fatal("initial and subsequent native assemblies differ")
	}
	var history []int64
	check(p.Pool.QueryRow(ctx, `SELECT array_agg(generation ORDER BY generation) FROM desired_states WHERE node_id=$1::uuid`, node.ID).Scan(&history))
	if !reflect.DeepEqual(history, []int64{1, 2}) {
		t.Fatal("initial activation published an intermediate deployment")
	}
}
