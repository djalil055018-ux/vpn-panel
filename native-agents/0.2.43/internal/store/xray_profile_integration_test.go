//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"vpn-platform/internal/model"
	"vpn-platform/internal/security"
	"vpn-platform/internal/subscriptioncompat"
	"vpn-platform/internal/xrayprofile"
)

// Registry rows here are synthetic fixtures, not a production adoption path.
// Owner preparation and physical single-writer cutover remain separate work.
func TestXrayProfileAdmissionAndClientLifecycleIntegration(t *testing.T) {
	ctx, p, tenant, importID, digest := botFixture(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	bootstrap := security.HashToken("synthetic-imported-profile-bootstrap")
	node, err := p.CreateNodeForRuntime(ctx, tenant, "Imported synthetic Xray", bootstrap, "xray")
	check(err)
	_, err = p.BootstrapAgentForRuntime(ctx, bootstrap, security.HashToken("synthetic-imported-profile-agent"), "0.2.31", "ubuntu", "24.04", "amd64", "xray")
	check(err)
	release, err := p.CreateCoreRelease(ctx, model.CoreReleaseRecord{Type: "xray", Version: "26.9.9", OS: "linux", Architecture: "amd64", DownloadURL: "https://example.invalid/imported.zip", SHA256: strings.Repeat("d", 64), Channel: "testing"})
	check(err)
	check(p.ApproveCoreRelease(ctx, release.ID))
	core := model.CoreRelease{Type: release.Type, Version: release.Version, DownloadURL: release.DownloadURL, SHA256: release.SHA256, Channel: release.Channel}
	check(p.SaveDesiredState(ctx, node.ID, model.DesiredState{Generation: 1, Core: core}, release.ID))
	cert, err := p.CreateNodeCertificate(ctx, node.ID, "profile.example.test", "letsencrypt", "http-01", "production", nil, true)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE node_certificates SET status='active',not_before=now()-interval '1 day',not_after=now()+interval '1 day' WHERE id=$1::uuid`, cert.ID)
	check(err)
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	inbounds := []any{}
	bindings := []model.XrayProfileBinding{}
	services := []model.ServiceSpec{}
	for i, kind := range []string{"raw", "grpc", "xhttp", "hysteria", "xhttp-tls"} {
		var id string
		check(p.Pool.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&id))
		port := []int{443, 8443, 4443, 443, 8444}[i]
		protocol, network, transport, security := "vless", kind, kind, "reality"
		if kind == "raw" {
			transport = "tcp"
		}
		if kind == "hysteria" {
			protocol, transport, security = "hysteria", "udp", "tls"
		}
		if kind == "xhttp-tls" {
			network, transport, security = "xhttp", "xhttp", "tls"
		}
		stream := map[string]any{"network": network, "security": security}
		settings := map[string]any{"clients": []any{}, "decryption": "none"}
		if protocol == "hysteria" {
			settings = map[string]any{"clients": []any{}, "version": 2}
			stream["hysteriaSettings"] = map[string]any{"version": 2}
		}
		if network == "grpc" {
			stream["grpcSettings"] = map[string]any{"serviceName": "original-grpc", "multiMode": true}
		}
		if network == "xhttp" {
			stream["xhttpSettings"] = map[string]any{"path": "/original-xhttp", "mode": "auto"}
		}
		svc := model.ServiceSpec{ID: id, Protocol: protocol, Listen: "0.0.0.0", Port: port, Transport: transport, Security: security}
		if protocol == "hysteria" {
			svc.Protocol = "hysteria2"
		}
		if security == "reality" {
			stream["realitySettings"] = map[string]any{"target": "profile.example.test:443", "serverNames": []string{"profile.example.test"}, "shortIds": []string{""}, "privateKey": key}
			svc.Reality = &model.RealitySpec{Destination: "profile.example.test:443", ServerName: "profile.example.test", Fingerprint: "chrome", ShortID: "", SecretRef: "reality/" + id}
		} else {
			stream["tlsSettings"] = map[string]any{"certificates": []any{map[string]any{"certificateFile": "/source/cert.pem", "keyFile": "/source/key.pem"}}}
			svc.TLS = &model.TLSSpec{CertificateID: cert.ID, ServerName: "profile.example.test"}
		}
		inbounds = append(inbounds, map[string]any{"tag": kind, "protocol": protocol, "listen": "0.0.0.0", "port": port, "settings": settings, "streamSettings": stream})
		bindings = append(bindings, model.XrayProfileBinding{ServiceID: id, InboundTag: kind})
		services = append(services, svc)
	}
	raw, err := json.Marshal(map[string]any{"inbounds": inbounds, "outbounds": []any{map[string]any{"tag": "DIRECT", "protocol": "freedom"}}})
	check(err)
	profile, _, err := xrayprofile.Project(raw, bindings)
	check(err)
	check(xrayprofile.ValidateServices(profile, services))
	attempt := model.DesiredState{Generation: 2, Core: core, XrayProfile: profile}
	if err = p.SaveDesiredState(ctx, node.ID, attempt, release.ID); !errors.Is(err, ErrXrayProfileHeld) {
		t.Fatal("unregistered imported graph accepted")
	}

	// A complete, source-bound prepared registry may hold disabled services only.
	tx, err := p.Pool.Begin(ctx)
	check(err)
	defer tx.Rollback(context.WithoutCancel(ctx))
	wire, err := json.Marshal(profile)
	check(err)
	_, err = tx.Exec(ctx, `INSERT INTO node_xray_profiles(node_id,tenant_id,import_id,inventory_sha256,source_node_id,source_profile_id,profile_sha256,profile)
 VALUES($1::uuid,$2::uuid,$3::uuid,$4,gen_random_uuid(),gen_random_uuid(),$5,$6::jsonb)`, node.ID, tenant, importID, digest, profile.SHA256, string(wire))
	check(err)
	for i, svc := range services {
		spec, err := json.Marshal(svc)
		check(err)
		_, err = tx.Exec(ctx, `INSERT INTO node_xray_profile_bindings(node_id,tenant_id,service_id,source_inbound_id,source_enabled,inbound_tag,service_spec)
 VALUES($1::uuid,$2::uuid,$3::uuid,gen_random_uuid(),true,$4,$5::jsonb)`, node.ID, tenant, svc.ID, bindings[i].InboundTag, string(spec))
		check(err)
		_, err = tx.Exec(ctx, `INSERT INTO vpn_services(id,tenant_id,node_id,name,protocol,listen,port,transport,security,enabled)
 VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,false)`, svc.ID, tenant, node.ID, bindings[i].InboundTag, svc.Protocol, svc.Listen, svc.Port, svc.Transport, svc.Security)
		check(err)
		if svc.Reality != nil {
			r := svc.Reality
			_, err = tx.Exec(ctx, `INSERT INTO vpn_service_reality(service_id,tenant_id,destination,server_name,fingerprint,short_id,secret_ref,public_key)
 VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)`, svc.ID, tenant, r.Destination, r.ServerName, r.Fingerprint, r.ShortID, r.SecretRef, profile.Bindings[i].RealityPublicKey)
			check(err)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO vpn_service_tls(service_id,tenant_id,node_id,certificate_id) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)`, svc.ID, tenant, node.ID, cert.ID)
			check(err)
		}
	}
	check(tx.Commit(ctx))
	if _, err = p.SetVPNServiceEnabledAndRebuild(ctx, services[0].ID, true); err == nil {
		t.Fatal("prepared node enabled without adoption")
	}
	if err = p.SaveDesiredState(ctx, node.ID, attempt, release.ID); !errors.Is(err, ErrXrayProfileHeld) {
		t.Fatal("prepared profile became assignable")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE node_xray_profiles SET state='active',adoption_sha256=$2,activated_at=now() WHERE node_id=$1::uuid`, node.ID, strings.Repeat("e", 64))
	check(err)
	if _, err = p.Pool.Exec(ctx, `UPDATE node_xray_profiles SET state='prepared' WHERE node_id=$1::uuid`, node.ID); err == nil {
		t.Fatal("adopted profile returned to preparation")
	}
	for _, svc := range services {
		_, err = p.SetVPNServiceEnabledAndRebuild(ctx, svc.ID, true)
		check(err)
	}

	_, err = p.PrepareBotBridge(ctx, tenant, importID, digest)
	check(err)
	_, err = p.PrepareRemnawaveNoResetQuota(ctx, importID, tenant, digest)
	check(err)
	publicAlias := syntheticPublicSubscription(t, ctx, p, tenant, importID, digest, services, profile)
	publicDeleted := false
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_clients SET remnawave_hold=false,status='active',expires_at=now()+interval '7 days' WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	_, err = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active',source_identity_reviewed=true,activated_at=now() WHERE tenant_id=$1::uuid`, tenant)
	check(err)
	mapping, err := p.RemnawaveImportClients(ctx, importID, 0, 250)
	check(err)
	clientID := mapping[0].ClientID
	for _, svc := range services {
		_, err = p.AttachVPNClientAndRebuild(ctx, svc.ID, clientID)
		check(err)
	}
	operator := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "operator"})
	current := func() model.DesiredState {
		t.Helper()
		var document []byte
		var state model.DesiredState
		check(p.Pool.QueryRow(ctx, `SELECT d.document FROM nodes n JOIN desired_states d ON d.node_id=n.id AND d.generation=n.desired_generation WHERE n.id=$1::uuid`, node.ID).Scan(&document))
		check(json.Unmarshal(document, &state))
		return state
	}
	assertAccess := func(want int) {
		t.Helper()
		state := current()
		if state.XrayProfile == nil || state.XrayProfile.SHA256 != profile.SHA256 || len(state.Services) != 5 {
			t.Fatal("profile lost during native lifecycle rebuild")
		}
		for _, svc := range state.Services {
			if len(svc.Clients) != want {
				t.Fatal("mixed transport authorization differs")
			}
		}
		_, err := xrayprofile.AuthorizationConfig(state.XrayProfile, state.Services)
		check(err)
		public, e := p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: publicAlias})
		if publicDeleted {
			if !errors.Is(e, ErrNotFound) {
				t.Fatal("deleted public alias resolved")
			}
		} else {
			check(e)
			if len(public.Hosts) != want*len(services) || public.Policy.Headers["profile-title"] != "external" {
				t.Fatal("public hosts or external policy differ from native access")
			}
			if want == 0 && public.Credential != "" {
				t.Fatal("ineligible account exposed runtime credential")
			}
			if want == 1 && public.Credential != state.Services[0].Clients[0].ID {
				t.Fatal("public credential differs from native runtime")
			}
			encoded, e := json.Marshal(public)
			check(e)
			if string(encoded) != "{}" {
				t.Fatal("private subscription snapshot serializes")
			}
		}
	}
	assertAccess(1)

	t.Run("MixedGroupForImportedAndNewClients", func(t *testing.T) {
		check := func(e error) {
			t.Helper()
			if e != nil {
				t.Fatal(e)
			}
		}
		newClient, e := p.CreateVPNClient(ctx, tenant, "New Main client", nil)
		check(e)
		b := security.HashToken("mixed-native-node")
		nativeNode, e := p.CreateNodeForRuntime(ctx, tenant, "Mixed native node", b, "xray")
		check(e)
		_, e = p.BootstrapAgentForRuntime(ctx, b, security.HashToken("mixed-native-agent"), "0.2.33", "ubuntu", "24.04", "amd64", "xray")
		check(e)
		check(p.SaveDesiredState(ctx, nativeNode.ID, model.DesiredState{Generation: 1, Core: core}, release.ID))
		address, port := "new-native.example.test", 443
		nativeService, e := p.CreateVPNService(ctx, nativeNode.ID, "New native REALITY", "vless", "0.0.0.0", port, "tcp", "reality", &address, &port)
		check(e)
		_, e = p.ConfigureVPNServiceReality(ctx, nativeService.ID, "example.test:443", "example.test", "firefox", "0123456789abcdef")
		check(e)
		_, e = p.Pool.Exec(ctx, `UPDATE vpn_service_reality SET public_key=$2 WHERE service_id=$1::uuid`, nativeService.ID, key)
		check(e)
		_, e = p.SetVPNServiceEnabledAndRebuild(ctx, nativeService.ID, true)
		check(e)
		plan, e := p.CreateVPNAccessPlan(ctx, tenant, "Main mixed", "main-mixed", true)
		check(e)
		for _, id := range append([]string{nativeService.ID}, services[0].ID, services[1].ID, services[2].ID, services[3].ID, services[4].ID) {
			_, e = p.SetVPNAccessPlanService(ctx, plan.ID, id, true)
			check(e)
		}
		for _, id := range []string{clientID, newClient.ID} {
			_, e = p.SetVPNClientAccessPlan(ctx, plan.ID, id, true)
			check(e)
		}
		verify := func(id string, want int) {
			t.Helper()
			connections, e := p.ListVPNClientConnections(ctx, id)
			check(e)
			if len(connections) != want {
				t.Fatalf("mixed group has %d profiles; want %d", len(connections), want)
			}
			client, e := p.GetVPNClient(ctx, id)
			check(e)
			for _, c := range connections {
				if c.UUID != client.VLESSUUID {
					t.Fatal("profile uses another account credential")
				}
			}
		}
		verify(clientID, 6)
		verify(newClient.ID, 6)
		snap, e := p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: publicAlias})
		check(e)
		if len(snap.Hosts) != 6 {
			t.Fatal("legacy link failed to include native group server")
		}
		snap, e = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{NativeClientID: clientID})
		check(e)
		if len(snap.Hosts) != 6 {
			t.Fatal("native link differs from legacy link")
		}

		t.Run("subscription names preserve native and imported runtime", func(t *testing.T) {
			var before, after string
			stateSQL := `SELECT md5(json_build_array(
              (SELECT json_agg(x ORDER BY id) FROM nodes x),
              (SELECT json_agg(x ORDER BY node_id,generation) FROM desired_states x),
              (SELECT json_agg(x ORDER BY id) FROM vpn_clients x),
              (SELECT json_agg(x ORDER BY id) FROM imported_subscription_revisions x))::text)`
			check(p.Pool.QueryRow(ctx, stateSQL).Scan(&before))
			labels := map[string]string{nativeService.ID: "🇳🇱 Нидерланды · REALITY & #1", services[0].ID: "🇷🇺 Россия · Основной"}
			original := map[string]string{}
			for id, label := range labels {
				old, e := p.GetVPNService(ctx, id)
				check(e)
				original[id] = old.SubscriptionDefaultName
				saved, e := p.SetVPNServiceSubscriptionName(ctx, id, label)
				check(e)
				if saved.SubscriptionName == nil || *saved.SubscriptionName != label || saved.SubscriptionDefaultName != original[id] {
					t.Fatal("saved label/default mismatch")
				}
			}
			for _, id := range []string{clientID, newClient.ID} {
				connections, e := p.ListVPNClientConnections(ctx, id)
				check(e)
				for _, c := range connections {
					if label, ok := labels[c.ServiceID]; ok {
						if c.SubscriptionName != label {
							t.Fatal("client did not receive custom name")
						}
						if len(c.ImportedProfile) > 0 {
							var h subscriptioncompat.Host
							check(json.Unmarshal(c.ImportedProfile, &h))
							if h.Name != label {
								t.Fatal("imported host kept original name")
							}
						}
					}
				}
			}
			renamed, e := p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: publicAlias})
			check(e)
			if renamed.Credential != snap.Credential || len(renamed.Hosts) != len(snap.Hosts) {
				t.Fatal("rename changed access")
			}
			for _, label := range labels {
				found := false
				for _, h := range renamed.Hosts {
					if h.Name == label {
						found = true
					}
				}
				if !found {
					t.Fatal("legacy subscription did not receive name")
				}
			}
			check(p.Pool.QueryRow(ctx, stateSQL).Scan(&after))
			if before != after {
				t.Fatal("rename changed VPN runtime or client identity")
			}
			other, e := p.CreateTenant(ctx, "Name foreign tenant")
			check(e)
			_, e = p.SetVPNServiceSubscriptionName(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: other.ID, Role: "operator"}), nativeService.ID, "foreign")
			if !errors.Is(e, ErrNotFound) {
				t.Fatal("cross-tenant rename was accepted")
			}
			for id := range labels {
				reset, e := p.SetVPNServiceSubscriptionName(ctx, id, "")
				check(e)
				if reset.SubscriptionName != nil || reset.SubscriptionDefaultName != original[id] {
					t.Fatal("reset failed to restore original label")
				}
			}
		})

		_, e = p.SetVPNAccessPlanService(ctx, plan.ID, services[0].ID, false)
		check(e)
		verify(newClient.ID, 5)
		_, e = p.SetVPNAccessPlanService(ctx, plan.ID, services[0].ID, true)
		check(e)
		_, e = p.SetVPNClientStatus(ctx, newClient.ID, "disabled")
		check(e)
		verify(newClient.ID, 0)
		_, e = p.SetVPNClientStatus(ctx, newClient.ID, "active")
		check(e)
		verify(newClient.ID, 6)
		past := time.Now().Add(-time.Hour)
		_, e = p.UpdateVPNClient(ctx, newClient.ID, nil, nil, &past, true)
		check(e)
		verify(newClient.ID, 0)
		for _, id := range []string{clientID, newClient.ID} {
			_, e = p.SetVPNClientAccessPlan(ctx, plan.ID, id, false)
			check(e)
		}
		_, e = p.SetVPNServiceEnabledAndRebuild(ctx, nativeService.ID, false)
		check(e)
	})
	pageContext := WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: tenant, Role: "viewer"})
	pages, e := p.ImportedSubscriptionPages(pageContext)
	check(e)
	if len(pages) != 1 || pages[0].Name != "Default" || pages[0].ViewPosition != 1 || string(pages[0].Config) != `{"synthetic":true}` {
		t.Fatal("source page config metadata")
	}
	if _, e = p.ImportedSubscriptionPages(ctx); !errors.Is(e, ErrNotFound) {
		t.Fatal("anonymous page enumeration")
	}
	foreign, e := p.CreateTenant(ctx, "Public foreign tenant")
	check(e)
	if _, e = p.ImportedSubscriptionPages(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "viewer"})); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant page enumeration")
	}
	_, e = p.ReadImportedSubscription(WithTenantPrincipal(ctx, model.TenantAPIToken{TenantID: foreign.ID, Role: "operator"}), ImportedSubscriptionLookup{Alias: publicAlias})
	if !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-tenant subscription snapshot")
	}
	native, e := p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{NativeClientID: clientID})
	check(e)
	if len(native.Hosts) != 5 {
		t.Fatal("native authenticated selector lost imported profiles")
	}
	_, e = p.SetVPNServiceEnabledAndRebuild(ctx, services[0].ID, false)
	check(e)
	limited, e := p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: publicAlias})
	check(e)
	if len(limited.Hosts) != 4 {
		t.Fatal("disabled service remained in public subscription")
	}
	_, e = p.SetVPNServiceEnabledAndRebuild(ctx, services[0].ID, true)
	check(e)
	_, e = p.DetachVPNClientAndRebuild(ctx, services[1].ID, clientID)
	check(e)
	limited, e = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: publicAlias})
	check(e)
	if len(limited.Hosts) != 4 {
		t.Fatal("removed native grant remained in public subscription")
	}
	_, e = p.AttachVPNClientAndRebuild(ctx, services[1].ID, clientID)
	check(e)
	var globalAlias string
	check(p.Pool.QueryRow(ctx, `SELECT alias FROM bot_subscription_aliases WHERE tenant_id=$1::uuid AND legacy_id=2 AND state='active'`, tenant).Scan(&globalAlias))
	global, e := p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: globalAlias})
	check(e)
	if len(global.Hosts) != 0 || global.Credential != "" || global.Policy.Headers["profile-title"] != "global" {
		t.Fatal("cross-account permissions or policy leaked")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	limited, e = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: publicAlias})
	check(e)
	if len(limited.Hosts) != 5 {
		t.Fatal("bot API pause incorrectly revoked public access")
	}
	if _, e = p.ImportedSubscriptionPages(pageContext); e != nil {
		t.Fatal("bot API pause revoked page config")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE bot_profiles SET state='active' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	_, e = p.Pool.Exec(ctx, `UPDATE imported_subscription_profiles SET state='paused' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	_, e = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: publicAlias})
	if !errors.Is(e, ErrNotFound) {
		t.Fatal("paused public profile resolved")
	}
	if _, e = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{NativeClientID: clientID}); !errors.Is(e, ErrNotFound) {
		t.Fatal("paused native imported subscription can fall back")
	}
	if _, e = p.ImportedSubscriptionPages(pageContext); !errors.Is(e, ErrNotFound) {
		t.Fatal("paused public page resolved")
	}
	_, e = p.Pool.Exec(ctx, `UPDATE imported_subscription_profiles SET state='active' WHERE tenant_id=$1::uuid`, tenant)
	check(e)
	if _, e = p.Pool.Exec(ctx, `UPDATE imported_subscription_profiles SET state='prepared',activated_at=NULL,activation_sha256=NULL WHERE tenant_id=$1::uuid`, tenant); e == nil {
		t.Fatal("active public profile returned to preparation")
	}
	for _, bad := range []string{"drop-profile", "inject-client", "omit-client", "wrong-core", "unapproved-artifact", "drop-service"} {
		state := current()
		state.Generation++
		switch bad {
		case "drop-profile":
			state.XrayProfile = nil
		case "inject-client":
			state.Services[0].Clients[0].ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		case "omit-client":
			state.Services[0].Clients = nil
		case "wrong-core":
			state.Core.Version = "26.7.28"
		case "unapproved-artifact":
			state.Core.SHA256 = strings.Repeat("0", 64)
		case "drop-service":
			state.Services = state.Services[1:]
		}
		if p.SaveDesiredState(ctx, node.ID, state, release.ID) == nil {
			t.Fatal("raw submission bypassed " + bad)
		}
	}
	for _, query := range []string{
		`UPDATE vpn_services SET port=19999 WHERE id=$1::uuid`,
		`UPDATE vpn_service_reality SET short_id='aa' WHERE service_id=$1::uuid`,
		`UPDATE vpn_service_reality SET public_key='replacement' WHERE service_id=$1::uuid`,
		`UPDATE node_xray_profile_bindings SET inbound_tag='replacement' WHERE service_id=$1::uuid`,
	} {
		if _, err = p.Pool.Exec(ctx, query, services[0].ID); err == nil {
			t.Fatal("database allowed imported identity drift")
		}
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.30' WHERE id=$1::uuid`, node.ID)
	check(err)
	if _, _, err = p.AgentAssignment(ctx, node.ID); !errors.Is(err, ErrNodeRuntime) {
		t.Fatal("downgraded Agent received imported assignment")
	}
	if _, _, err = p.LegacyAgentDesiredState(ctx, node.ID); !errors.Is(err, ErrXrayProfileLegacy) {
		t.Fatal("legacy desired-state route bypassed imported capability gate")
	}
	var fenceID string
	check(p.Pool.QueryRow(ctx, `INSERT INTO execution_fence_requests(tenant_id,node_id,deployment_id,generation,execution_id,execution_epoch,target_owner_instance_id,reason)
 SELECT n.tenant_id,n.id,d.id,d.generation,d.execution_id,d.execution_epoch,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'synthetic imported downgrade fence'
 FROM nodes n JOIN deployments d ON d.node_id=n.id AND d.generation=n.desired_generation WHERE n.id=$1::uuid RETURNING id::text`, node.ID).Scan(&fenceID))
	if assignment, ok, e := p.AgentAssignment(ctx, node.ID); e != nil || !ok || assignment.FenceRequest == nil || assignment.FenceRequest.ID != fenceID {
		t.Fatal("capability gate suppressed physical stop request")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE execution_fence_requests SET state='cancelled',cancelled_at=now() WHERE id=$1::uuid`, fenceID)
	check(err)
	if _, _, err = p.AgentAssignment(ctx, node.ID); !errors.Is(err, ErrNodeRuntime) {
		t.Fatal("cancelled fence bypassed capability gate")
	}
	if _, err = p.RebuildNodeDesiredState(ctx, node.ID); err == nil {
		t.Fatal("downgraded Agent accepted new imported generation")
	}
	_, err = p.Pool.Exec(ctx, `UPDATE nodes SET agent_version='0.2.31' WHERE id=$1::uuid`, node.ID)
	check(err)
	if _, ok, e := p.AgentAssignment(ctx, node.ID); e != nil || !ok {
		t.Fatal("supported Agent did not receive profile")
	}
	if _, _, err = p.LegacyAgentDesiredState(ctx, node.ID); !errors.Is(err, ErrXrayProfileLegacy) {
		t.Fatal("imported profile bypassed execution/fence envelope")
	}

	_, err = p.BotUserAction(operator, 1, "disable", strings.Repeat("1", 64), 0)
	check(err)
	assertAccess(0)
	_, err = p.BotUserAction(operator, 1, "enable", strings.Repeat("2", 64), 0)
	check(err)
	assertAccess(1)
	expired := time.Now().Add(-time.Hour)
	_, err = p.UpdateVPNClient(ctx, clientID, nil, nil, &expired, true)
	check(err)
	assertAccess(0)
	_, err = p.UpdateVPNClient(ctx, clientID, nil, nil, nil, true)
	check(err)
	assertAccess(1)
	_, err = p.Pool.Exec(ctx, `UPDATE vpn_client_continuous_quotas SET limit_bytes=150,baseline_bytes=100,uplink_bytes=0,downlink_bytes=0 WHERE client_id=$1::uuid`, clientID)
	check(err)
	check(p.SaveTrafficDelivery(ctx, node.ID, model.TrafficDelivery{RecordedAt: time.Now().UTC(), Snapshot: model.ClientTrafficSnapshot{Epoch: strings.Repeat("b", 32), Sequence: 1, Clients: []model.ClientTraffic{{ClientID: clientID, Uplink: 80}}}}))
	assertAccess(0)
	_, err = p.BotUserAction(operator, 1, "reset-traffic", strings.Repeat("3", 64), 0)
	check(err)
	assertAccess(1)
	before := current().Services[0].Clients[0].ID
	_, err = p.BotUserAction(operator, 1, "revoke", strings.Repeat("4", 64), 0)
	check(err)
	_, err = p.ReadImportedSubscription(ctx, ImportedSubscriptionLookup{Alias: publicAlias})
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked public alias resolved")
	}
	check(p.Pool.QueryRow(ctx, `SELECT alias FROM bot_subscription_aliases WHERE tenant_id=$1::uuid AND legacy_id=1 AND state='active'`, tenant).Scan(&publicAlias))
	assertAccess(1)
	for _, svc := range current().Services {
		if svc.Clients[0].ID == before {
			t.Fatal("old UUID survived credential rotation")
		}
	}
	client, err := p.GetVPNClient(ctx, clientID)
	check(err)
	deleted, err := p.DeleteVPNClient(ctx, clientID, client.Name)
	check(err)
	if !deleted.Deleted || len(deleted.Rebuilds) != 1 {
		t.Fatal("mixed profile deletion did not rebuild its node")
	}
	publicDeleted = true
	assertAccess(0)
	check(p.RevokeCoreRelease(ctx, release.ID))
	if _, _, err = p.AgentAssignment(ctx, node.ID); !errors.Is(err, ErrPinnedCoreReleaseUnavailable) {
		t.Fatal("revoked artifact remained assignable")
	}
}

func TestXrayProfileSocketIdentityIntegration(t *testing.T) {
	ctx, p := deletionStore(t)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, err := p.CreateTenant(ctx, "Synthetic socket uniqueness")
	check(err)
	node, err := p.CreateNodeForRuntime(ctx, tenant.ID, "Socket families", security.HashToken("synthetic-socket-bootstrap"), "xray")
	check(err)
	insert := func(protocol, transport, security string, port int) error {
		_, err := p.Pool.Exec(ctx, `INSERT INTO vpn_services(tenant_id,node_id,name,protocol,transport,security,port,enabled)
 VALUES($1::uuid,$2::uuid,'synthetic socket',$3,$4,$5,$6,false)`, tenant.ID, node.ID, protocol, transport, security, port)
		return err
	}
	check(insert("vless", "tcp", "reality", 19443))
	check(insert("wireguard", "udp", "wireguard", 19443))
	for _, v := range []struct{ protocol, transport, security string }{{"vless", "grpc", "reality"}, {"wireguard", "udp", "wireguard"}, {"shadowsocks", "tcp,udp", "shadowsocks"}} {
		if insert(v.protocol, v.transport, v.security, 19443) == nil {
			t.Fatal("duplicate socket family accepted")
		}
	}
	check(insert("shadowsocks", "tcp,udp", "shadowsocks", 19444))
	for _, v := range []struct{ protocol, transport, security string }{{"vless", "tcp", "reality"}, {"wireguard", "udp", "wireguard"}} {
		if insert(v.protocol, v.transport, v.security, 19444) == nil {
			t.Fatal("combined transport did not reserve both families")
		}
	}
	check(insert("vless", "future-unknown", "reality", 19445))
	for _, v := range []struct{ protocol, transport, security string }{{"vless", "tcp", "reality"}, {"wireguard", "udp", "wireguard"}} {
		if insert(v.protocol, v.transport, v.security, 19445) == nil {
			t.Fatal("unknown transport did not reserve both families")
		}
	}
	if insert("hysteria2", "udp", "tls", 19446) == nil {
		t.Fatal("ordinary Xray node acquired unbound Hysteria service")
	}
}
