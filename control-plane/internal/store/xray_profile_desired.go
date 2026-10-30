package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

var ErrXrayProfileHeld = errors.New("imported Xray node is not prepared for activation")
var ErrXrayProfileIdentity = errors.New("imported Xray state differs from its reviewed node profile")
var ErrXrayProfileLegacy = errors.New("imported Xray profiles require the execution assignment endpoint")

// The legacy endpoint has no physical execution/fence envelope. Even a modern
// Agent must use /assignment for imported profiles; old readers ignore new JSON.
func (p *Postgres) LegacyAgentDesiredState(ctx context.Context, nodeID string) (model.DesiredState, bool, error) {
	state, exists, err := p.LatestDesiredState(ctx, nodeID)
	if err != nil || !exists {
		return state, exists, err
	}
	if state.XrayProfile != nil || state.XrayCascades != nil {
		return model.DesiredState{}, false, ErrXrayProfileLegacy
	}
	if err = p.validateXrayProfileAssignment(ctx, nodeID, state); err != nil {
		return model.DesiredState{}, false, err
	}
	return state, true, nil
}

type xrayProfileQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func registeredXrayProfile(ctx context.Context, q xrayProfileQuery, nodeID string) (*model.XrayProfileSpec, string, string, error) {
	var raw []byte
	var digest, state, agent string
	err := q.QueryRow(ctx, `SELECT p.profile,COALESCE(p.profile_sha256,''),COALESCE(p.state,''),COALESCE(n.agent_version,'')
 FROM nodes n LEFT JOIN node_xray_profiles p ON p.node_id=n.id AND p.tenant_id=n.tenant_id
 WHERE n.id=$1::uuid`, nodeID).Scan(&raw, &digest, &state, &agent)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", "", ErrNotFound
	}
	if err != nil {
		return nil, "", "", err
	}
	if len(raw) == 0 {
		return nil, "", agent, nil
	}
	var profile model.XrayProfileSpec
	if json.Unmarshal(raw, &profile) != nil || profile.SHA256 != digest || xrayprofile.Validate(&profile) != nil {
		return nil, "", "", ErrXrayProfileIdentity
	}
	return &profile, state, agent, nil
}

func matchRegisteredXrayState(expected *model.XrayProfileSpec, status, agent string, state model.DesiredState) error {
	if state.XrayCascades != nil && (!model.XrayCascadeAgentCompatible(agent) || !xrayprofile.CoreCompatible(state.Core)) {
		return ErrNodeRuntime
	}
	if expected == nil {
		if state.XrayProfile != nil {
			return ErrXrayProfileHeld
		}
		return nil
	}
	if status != "active" {
		if status != "prepared" || state.XrayProfile != nil || len(state.Services) > 0 {
			return ErrXrayProfileHeld
		}
		return nil
	}
	if state.XrayProfile == nil || state.XrayProfile.SHA256 != expected.SHA256 || xrayprofile.ValidateServices(state.XrayProfile, state.Services) != nil {
		return ErrXrayProfileIdentity
	}
	if !xrayprofile.AgentCompatible(agent) || !xrayprofile.CoreCompatible(state.Core) {
		return ErrNodeRuntime
	}
	return nil
}

// The node is locked by saveDesiredStateTx. Membership must be the exact native
// authorized view, even for direct JSON submissions, recovery and core rollouts.
func validateXrayProfileDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState, releaseID string) error {
	profile, status, agent, err := registeredXrayProfile(ctx, tx, nodeID)
	if err != nil {
		return err
	}
	if err = matchRegisteredXrayState(profile, status, agent, state); err != nil {
		return err
	}
	if profile == nil || status != "active" {
		return nil
	}
	var approved bool
	err = tx.QueryRow(ctx, `SELECT approved AND NOT revoked AND core_type='xray' AND version=$2
 AND sha256=$3 AND download_url=$4 AND os='linux' AND architecture='amd64'
 FROM core_releases WHERE id=$1::uuid FOR SHARE`, releaseID, state.Core.Version, state.Core.SHA256, state.Core.DownloadURL).Scan(&approved)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !approved) {
		return ErrPinnedCoreReleaseUnavailable
	}
	if err != nil {
		return err
	}

	rows, err := tx.Query(ctx, `SELECT b.service_spec,s.enabled
 FROM node_xray_profile_bindings b JOIN vpn_services s ON s.id=b.service_id AND s.tenant_id=b.tenant_id AND s.node_id=b.node_id
 WHERE b.node_id=$1::uuid ORDER BY b.service_id`, nodeID)
	if err != nil {
		return err
	}
	expected := map[string]model.ServiceSpec{}
	all := map[string]bool{}
	for rows.Next() {
		var raw []byte
		var enabled bool
		var service model.ServiceSpec
		if err = rows.Scan(&raw, &enabled); err != nil {
			rows.Close()
			return err
		}
		if json.Unmarshal(raw, &service) != nil || service.ID == "" || len(service.Clients) != 0 {
			rows.Close()
			return ErrXrayProfileIdentity
		}
		all[service.ID] = true
		if enabled {
			expected[service.ID] = service
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(all) != len(profile.Bindings) || len(expected) != len(state.Services) {
		return ErrXrayProfileIdentity
	}
	for _, binding := range profile.Bindings {
		if !all[binding.ServiceID] {
			return ErrXrayProfileIdentity
		}
	}
	for _, actual := range state.Services {
		base, ok := expected[actual.ID]
		if !ok {
			return ErrXrayProfileIdentity
		}
		delete(expected, actual.ID)
		actualClients := actual.Clients
		actual.Clients = nil
		base.Clients = nil
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(base)
		if !bytes.Equal(a, b) {
			return ErrXrayProfileIdentity
		}
		if base.TLS != nil {
			var valid bool
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_service_tls t JOIN node_certificates c
 ON c.id=t.certificate_id AND c.node_id=t.node_id AND c.tenant_id=t.tenant_id
 WHERE t.service_id=$1::uuid AND t.node_id=$2::uuid AND c.id=$3::uuid AND c.domain=$4
 AND c.environment='production' AND c.status IN ('active','renewing') AND c.not_before<=now() AND c.not_after>now())`, base.ID, nodeID, base.TLS.CertificateID, base.TLS.ServerName).Scan(&valid)
			if err != nil {
				return err
			}
			if !valid {
				return ErrVPNServiceTLSInvalid
			}
		}
		clients, err := tx.Query(ctx, `SELECT c.vless_uuid::text,c.id::text FROM vpn_effective_client_services cs
 JOIN vpn_clients c ON c.id=cs.client_id AND c.tenant_id=cs.tenant_id
 WHERE cs.service_id=$1::uuid AND c.status='active' AND NOT c.remnawave_hold
 AND (c.expires_at IS NULL OR c.expires_at>now()) AND NOT vpn_client_quota_exceeded(c.id)`, base.ID)
		if err != nil {
			return err
		}
		allowed := map[string]bool{}
		for clients.Next() {
			var id, stats string
			if err = clients.Scan(&id, &stats); err != nil {
				clients.Close()
				return err
			}
			allowed[id+"/"+stats] = true
		}
		err = clients.Err()
		clients.Close()
		if err != nil {
			return err
		}
		if len(allowed) != len(actualClients) {
			return ErrXrayProfileIdentity
		}
		for _, c := range actualClients {
			key := c.ID + "/" + c.StatsKey
			if !allowed[key] {
				return ErrXrayProfileIdentity
			}
			delete(allowed, key)
		}
	}
	return nil
}

// Recheck the parser floor on assignment, so an Agent downgrade cannot silently
// discard the profile. Physical fence requests are delivered before this gate.
func (p *Postgres) validateXrayProfileAssignment(ctx context.Context, nodeID string, state model.DesiredState) error {
	profile, status, agent, err := registeredXrayProfile(ctx, p.Pool, nodeID)
	if err != nil {
		return err
	}
	if err = matchRegisteredXrayState(profile, status, agent, state); err != nil {
		return err
	}
	if profile == nil || status != "active" {
		return nil
	}
	var approved bool
	err = p.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM deployments d JOIN core_releases r ON r.id=d.core_release_id
 WHERE d.node_id=$1::uuid AND d.generation=$2 AND r.approved AND NOT r.revoked AND r.core_type='xray'
 AND r.version=$3 AND r.sha256=$4 AND r.download_url=$5 AND r.os='linux' AND r.architecture='amd64')`, nodeID, state.Generation, state.Core.Version, state.Core.SHA256, state.Core.DownloadURL).Scan(&approved)
	if err != nil {
		return err
	}
	if !approved {
		return ErrPinnedCoreReleaseUnavailable
	}
	return nil
}
