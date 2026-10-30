package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

var xrayPreparationUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var xrayPreparationDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type XrayProfileTLSAssignment struct {
	SourceInboundID string `json:"source_inbound_id"`
	CertificateID   string `json:"certificate_id"`
}
type XrayProfilePreparation struct {
	NodeID   string `json:"node_id"`
	ImportID string `json:"import_id"`
	// Registry provenance stays immutable when a later user-only delta is reviewed.
	InventorySHA256 string                      `json:"inventory_sha256"`
	ReviewedSHA256  string                      `json:"reviewed_sha256"`
	ProfileSHA256   string                      `json:"profile_sha256"`
	Services        []xrayprofile.SourceService `json:"services"`
	State           string                      `json:"state"`
}

// PrepareXrayProfile binds an unused native Xray node to a reviewed source node.
// It writes only disabled services and a prepared registry. It never releases
// migration holds, grants access, changes generations or contacts an Agent.
func (p *Postgres) PrepareXrayProfile(ctx context.Context, tenant, importID, nodeID, sourceNodeID, reviewedSHA string, tls []XrayProfileTLSAssignment) (out XrayProfilePreparation, err error) {
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	for _, id := range []string{tenant, importID, nodeID, sourceNodeID} {
		if !xrayPreparationUUID.MatchString(id) {
			return out, ErrXrayProfileIdentity
		}
	}
	if !xrayPreparationDigest.MatchString(reviewedSHA) || len(tls) > 128 {
		return out, ErrXrayProfileIdentity
	}
	tlsIDs := map[string]string{}
	certIDs := map[string]bool{}
	for _, a := range tls {
		if !xrayPreparationUUID.MatchString(a.SourceInboundID) || !xrayPreparationUUID.MatchString(a.CertificateID) || tlsIDs[a.SourceInboundID] != "" {
			return out, ErrXrayProfileIdentity
		}
		tlsIDs[a.SourceInboundID] = a.CertificateID
		certIDs[a.CertificateID] = true
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	defer func() {
		var e *pgconn.PgError
		if errors.As(err, &e) && (e.Code == "23505" || e.Code == "23503" || e.Code == "23514" || e.Code == "55000") {
			err = ErrXrayProfileIdentity
		}
	}()
	var origin string
	err = tx.QueryRow(ctx, `SELECT source_origin FROM remnawave_imports WHERE id=$1::uuid AND tenant_id=$2::uuid AND state='held'`, importID, tenant).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103509,hashtext($1))`, origin); err != nil {
		return out, err
	}
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	var raw []byte
	var digest string
	err = tx.QueryRow(ctx, `SELECT r.inventory,h.inventory_sha256 FROM `+remnawaveCurrentFrom+` WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid AND i.state='held' FOR UPDATE OF h`, importID, tenant).Scan(&raw, &digest)
	if err != nil {
		return out, err
	}
	if digest != reviewedSHA {
		return out, ErrRemnawaveReview
	}
	requirements, err := xrayprofile.SourceNodeRequirements(raw, sourceNodeID)
	if err != nil {
		return out, ErrXrayProfileIdentity
	}
	requiredTLS := 0
	for _, r := range requirements {
		if r.Security == "tls" {
			requiredTLS++
			if tlsIDs[r.ID] == "" {
				return out, ErrVPNServiceTLSInvalid
			}
		} else if tlsIDs[r.ID] != "" {
			return out, ErrVPNServiceTLSInvalid
		}
	}
	if requiredTLS != len(tlsIDs) {
		return out, ErrVPNServiceTLSInvalid
	}

	// Certificate locks precede service/node locks, matching native TLS mutation.
	sortedCerts := []string{}
	for id := range certIDs {
		sortedCerts = append(sortedCerts, id)
	}
	sort.Strings(sortedCerts)
	certificates := map[string]model.TLSSpec{}
	for _, id := range sortedCerts {
		c := model.TLSSpec{CertificateID: id}
		err = tx.QueryRow(ctx, `SELECT domain FROM node_certificates WHERE id=$1::uuid AND node_id=$2::uuid AND tenant_id=$3::uuid AND environment='production' AND status IN ('active','renewing') AND not_before<=now() AND not_after>now() FOR SHARE`, id, nodeID, tenant).Scan(&c.ServerName)
		if errors.Is(err, pgx.ErrNoRows) {
			return out, ErrVPNServiceTLSInvalid
		}
		if err != nil {
			return out, err
		}
		var mismatchedImport bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM imported_tls_certificates WHERE certificate_id=$1::uuid AND (import_id<>$2::uuid OR source_node_id<>$3::uuid))`, id, importID, sourceNodeID).Scan(&mismatchedImport)
		if err != nil {
			return out, err
		}
		if mismatchedImport {
			return out, ErrVPNServiceTLSInvalid
		}
		certificates[id] = c
	}
	var runtime string
	var generation int64
	err = tx.QueryRow(ctx, `SELECT runtime_core,desired_generation FROM nodes WHERE id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, nodeID, tenant).Scan(&runtime, &generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if runtime != "xray" || generation != 0 {
		return out, ErrXrayProfileHeld
	}
	var history bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM desired_states WHERE node_id=$1::uuid) OR EXISTS(SELECT 1 FROM deployments WHERE node_id=$1::uuid) OR EXISTS(SELECT 1 FROM node_client_traffic_cursors WHERE node_id=$1::uuid)`, nodeID).Scan(&history)
	if err != nil {
		return out, err
	}
	if history {
		return out, ErrXrayProfileHeld
	}

	var previousImport, previousSource, previousProfile, previousSHA, status, profileSHA string
	var previousRaw []byte
	err = tx.QueryRow(ctx, `SELECT import_id::text,source_node_id::text,source_profile_id::text,inventory_sha256,state,profile_sha256,profile FROM node_xray_profiles WHERE node_id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, nodeID, tenant).Scan(&previousImport, &previousSource, &previousProfile, &previousSHA, &status, &profileSHA, &previousRaw)
	existing := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if existing && (previousImport != importID || previousSource != sourceNodeID || status != "prepared") {
		return out, ErrXrayProfileHeld
	}
	assignments := []xrayprofile.SourceServiceAssignment{}
	oldBindings := map[string]xrayprofile.SourceService{}
	if existing {
		rows, e := tx.Query(ctx, `SELECT source_inbound_id::text,inbound_tag,source_enabled,service_spec FROM node_xray_profile_bindings WHERE node_id=$1::uuid AND tenant_id=$2::uuid`, nodeID, tenant)
		if e != nil {
			return out, e
		}
		for rows.Next() {
			var b xrayprofile.SourceService
			var wire []byte
			if e = rows.Scan(&b.InboundID, &b.InboundTag, &b.Enabled, &wire); e != nil {
				rows.Close()
				return out, e
			}
			if json.Unmarshal(wire, &b.Service) != nil {
				rows.Close()
				return out, ErrXrayProfileIdentity
			}
			oldBindings[b.InboundID] = b
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return out, e
		}
		if len(oldBindings) != len(requirements) {
			return out, ErrXrayProfileIdentity
		}
	} else {
		var used bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_services WHERE node_id=$1::uuid)`, nodeID).Scan(&used); err != nil {
			return out, err
		}
		if used {
			return out, ErrXrayProfileHeld
		}
	}
	for _, r := range requirements {
		a := xrayprofile.SourceServiceAssignment{InboundID: r.ID}
		if existing {
			b, ok := oldBindings[r.ID]
			if !ok {
				return out, ErrXrayProfileIdentity
			}
			a.ServiceID = b.Service.ID
		} else if err = tx.QueryRow(ctx, "SELECT gen_random_uuid()::text").Scan(&a.ServiceID); err != nil {
			return out, err
		}
		if r.Security == "tls" {
			c := certificates[tlsIDs[r.ID]]
			a.TLS = &c
		}
		assignments = append(assignments, a)
	}
	projected, err := xrayprofile.ProjectSourceNode(raw, sourceNodeID, assignments)
	if err != nil || projected.InventorySHA256 != digest {
		return out, ErrXrayProfileIdentity
	}
	out = XrayProfilePreparation{NodeID: nodeID, ImportID: importID, InventorySHA256: digest, ReviewedSHA256: digest, ProfileSHA256: projected.Profile.SHA256, Services: projected.Services, State: "prepared"}
	if existing {
		var previous model.XrayProfileSpec
		if json.Unmarshal(previousRaw, &previous) != nil || previousProfile != projected.ProfileID || profileSHA != projected.Profile.SHA256 || previous.SHA256 != profileSHA || xrayprofile.Validate(&previous) != nil {
			return out, ErrXrayProfileIdentity
		}
		for _, b := range projected.Services {
			if !reflect.DeepEqual(b, oldBindings[b.InboundID]) {
				return out, ErrXrayProfileIdentity
			}
		}
		out.InventorySHA256 = previousSHA
	} else {
		wire, e := json.Marshal(projected.Profile)
		if e != nil {
			return out, e
		}
		_, err = tx.Exec(ctx, `INSERT INTO node_xray_profiles(node_id,tenant_id,import_id,inventory_sha256,source_node_id,source_profile_id,profile_sha256,profile) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6::uuid,$7,$8::jsonb)`, nodeID, tenant, importID, digest, sourceNodeID, projected.ProfileID, projected.Profile.SHA256, string(wire))
		if err != nil {
			return out, err
		}
		for _, b := range projected.Services {
			s := b.Service
			wire, e := json.Marshal(s)
			if e != nil {
				return out, e
			}
			_, err = tx.Exec(ctx, `INSERT INTO node_xray_profile_bindings(node_id,tenant_id,service_id,source_inbound_id,source_enabled,inbound_tag,service_spec) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7::jsonb)`, nodeID, tenant, s.ID, b.InboundID, b.Enabled, b.InboundTag, string(wire))
			if err != nil {
				return out, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO vpn_services(id,tenant_id,node_id,name,protocol,listen,port,transport,security,enabled) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,false)`, s.ID, tenant, nodeID, b.InboundTag, s.Protocol, s.Listen, s.Port, s.Transport, s.Security)
			if err != nil {
				return out, err
			}
			if r := s.Reality; r != nil {
				public := ""
				for _, binding := range projected.Profile.Bindings {
					if binding.ServiceID == s.ID {
						public = binding.RealityPublicKey
					}
				}
				_, err = tx.Exec(ctx, `INSERT INTO vpn_service_reality(service_id,tenant_id,destination,server_name,fingerprint,short_id,secret_ref,public_key) VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8)`, s.ID, tenant, r.Destination, r.ServerName, r.Fingerprint, r.ShortID, r.SecretRef, public)
			} else {
				_, err = tx.Exec(ctx, `INSERT INTO vpn_service_tls(service_id,tenant_id,node_id,certificate_id) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)`, s.ID, tenant, nodeID, s.TLS.CertificateID)
			}
			if err != nil {
				return out, err
			}
		}
	}
	// An idempotent request also verifies that native metadata has not drifted.
	var clean bool
	err = tx.QueryRow(ctx, `SELECT NOT EXISTS(
 SELECT 1 FROM vpn_services s LEFT JOIN node_xray_profile_bindings b ON b.service_id=s.id
 LEFT JOIN vpn_service_reality r ON r.service_id=s.id LEFT JOIN vpn_service_tls t ON t.service_id=s.id
 WHERE s.node_id=$1::uuid AND (b.service_id IS NULL OR s.enabled OR s.tenant_id<>$2::uuid
 OR (s.protocol,s.listen,s.port,s.transport,s.security) IS DISTINCT FROM
 (b.service_spec->>'protocol',b.service_spec->>'listen',(b.service_spec->>'port')::integer,b.service_spec->>'transport',b.service_spec->>'security')
 OR (s.security='reality' AND (r.service_id IS NULL OR
 (r.destination,r.server_name,r.short_id,r.secret_ref,r.fingerprint) IS DISTINCT FROM
 (b.service_spec->'reality'->>'destination',b.service_spec->'reality'->>'server_name',b.service_spec->'reality'->>'short_id',b.service_spec->'reality'->>'secret_ref',b.service_spec->'reality'->>'fingerprint')))
 OR (s.security='tls' AND t.certificate_id::text IS DISTINCT FROM b.service_spec->'tls'->>'certificate_id')
 OR EXISTS(SELECT 1 FROM vpn_effective_client_services e WHERE e.service_id=s.id)))
 AND (SELECT count(*) FROM vpn_services WHERE node_id=$1::uuid)=$3`, nodeID, tenant, len(projected.Services)).Scan(&clean)
	if err != nil {
		return out, err
	}
	if !clean {
		return out, ErrXrayProfileIdentity
	}
	if !existing {
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2::uuid,'xray_profile.prepared',$3,$4,jsonb_build_object('import_id',$5::text,'inventory_sha256',$6::text,'profile_sha256',$7::text,'services',$8::integer,'state','prepared'))`, tenant, nodeID, actor, actorID, importID, digest, projected.Profile.SHA256, len(projected.Services))
		if err != nil {
			return out, err
		}
	}
	return out, tx.Commit(ctx)
}
