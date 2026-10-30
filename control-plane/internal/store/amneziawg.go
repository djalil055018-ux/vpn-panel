package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
	"vpn-platform/internal/model"
)

var ErrAmneziaWGConfiguration = errors.New("AmneziaWG requires a supported version and a dedicated AmneziaWG node")

type AmneziaWGServiceConfiguration struct {
	ServiceID string    `json:"service_id"`
	Version   string    `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (p *Postgres) GetVPNServiceAmneziaWG(ctx context.Context, serviceID string) (AmneziaWGServiceConfiguration, error) {
	var out AmneziaWGServiceConfiguration
	var tenantID string
	err := p.Pool.QueryRow(ctx, `SELECT a.service_id::text,a.version,a.updated_at,a.tenant_id::text FROM vpn_service_amneziawg a
 JOIN vpn_services s ON s.id=a.service_id AND s.tenant_id=a.tenant_id JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
 WHERE a.service_id=$1::uuid AND s.protocol='amneziawg' AND n.runtime_core='amneziawg'`, serviceID).Scan(&out.ServiceID, &out.Version, &out.UpdatedAt, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err == nil && !tenantScopeAllowed(ctx, tenantID) {
		return AmneziaWGServiceConfiguration{}, ErrNotFound
	}
	return out, err
}

// Selecting the same dialect is idempotent. A different dialect gets its own
// shared settings while preserving the service's WireGuard identity and peers.
// Configuration, audit and enabled-service rebuild commit atomically.
func (p *Postgres) ConfigureVPNServiceAmneziaWG(ctx context.Context, serviceID, version string) (AmneziaWGServiceConfiguration, int64, error) {
	var out AmneziaWGServiceConfiguration
	if !model.ValidAmneziaWGVersion(version) {
		return out, 0, ErrAmneziaWGConfiguration
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var nodeID, tenantID, runtime, protocol, status string
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT s.node_id::text,s.tenant_id::text,n.runtime_core,s.protocol,n.status,s.enabled
 FROM vpn_services s JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id WHERE s.id=$1::uuid FOR UPDATE OF n,s`, serviceID).Scan(&nodeID, &tenantID, &runtime, &protocol, &status, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, 0, ErrNotFound
	}
	if err != nil {
		return out, 0, err
	}
	if !tenantScopeAllowed(ctx, tenantID) {
		return out, 0, ErrNotFound
	}
	if status == "retired" {
		return out, 0, ErrNodeRetired
	}
	if runtime != "amneziawg" || protocol != "amneziawg" {
		return out, 0, ErrAmneziaWGConfiguration
	}
	err = tx.QueryRow(ctx, `SELECT service_id::text,version,updated_at FROM vpn_service_amneziawg WHERE service_id=$1::uuid FOR UPDATE`, serviceID).Scan(&out.ServiceID, &out.Version, &out.UpdatedAt)
	if err == nil && out.Version == version {
		return out, 0, tx.Commit(ctx)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, 0, err
	}
	spec, err := model.NewAmneziaWGSpec(version)
	if err != nil {
		return out, 0, err
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return out, 0, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO vpn_service_amneziawg(service_id,tenant_id,version,settings) VALUES($1::uuid,$2::uuid,$3,$4::jsonb)
 ON CONFLICT(service_id) DO UPDATE SET version=EXCLUDED.version,settings=EXCLUDED.settings,updated_at=now()
 RETURNING service_id::text,version,updated_at`, serviceID, tenantID, version, raw).Scan(&out.ServiceID, &out.Version, &out.UpdatedAt)
	if err != nil {
		return out, 0, err
	}
	var generation int64
	if enabled {
		state, release, err := buildNodeDesiredStateTx(ctx, tx, nodeID)
		if err != nil {
			return out, 0, err
		}
		if err = saveDesiredStateTx(ctx, tx, nodeID, state, release); err != nil {
			return out, 0, err
		}
		generation = state.Generation
	}
	actor, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload)
 VALUES($1::uuid,$2::uuid,'vpn_service.amneziawg_configured',$3,$4,jsonb_build_object('service_id',$5::text,'version',$6::text))`, tenantID, nodeID, actor, actorID, serviceID, version)
	if err != nil {
		return out, 0, err
	}
	return out, generation, tx.Commit(ctx)
}

func fillAmneziaWGSettingsTx(ctx context.Context, tx pgx.Tx, services []model.ServiceSpec) error {
	for i := range services {
		s := &services[i]
		if s.Protocol != "amneziawg" {
			continue
		}
		var version string
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT a.version,a.settings FROM vpn_service_amneziawg a JOIN vpn_services s ON s.id=a.service_id AND s.tenant_id=a.tenant_id WHERE a.service_id=$1::uuid`, s.ID).Scan(&version, &raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAmneziaWGConfiguration
		}
		if err != nil {
			return err
		}
		var spec model.AmneziaWGSpec
		if json.Unmarshal(raw, &spec) != nil || spec.Version != version || spec.Validate() != nil {
			return ErrAmneziaWGConfiguration
		}
		s.AmneziaWG = &spec
	}
	return nil
}
