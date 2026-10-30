package store

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

var ErrVPNServiceTLSInvalid = errors.New("TLS service requires a valid production certificate on the same tenant and node")
var ErrCertificateInUse = errors.New("certificate is assigned to a VPN service")

type VPNServiceTLS struct {
	ServiceID     string `json:"service_id"`
	CertificateID string `json:"certificate_id"`
	ServerName    string `json:"server_name"`
}

func (p *Postgres) GetVPNServiceTLS(ctx context.Context, id string) (VPNServiceTLS, error) {
	var out VPNServiceTLS
	err := p.Pool.QueryRow(ctx, `SELECT t.service_id::text,t.certificate_id::text,c.domain FROM vpn_service_tls t JOIN node_certificates c ON c.id=t.certificate_id WHERE t.service_id=$1::uuid`, id).Scan(&out.ServiceID, &out.CertificateID, &out.ServerName)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}

// Certificate lock precedes the service lock, matching archive. Mutations and
// rebuild commit together; cross-node certificates are also forbidden by FK.
func (p *Postgres) ConfigureVPNServiceTLS(ctx context.Context, serviceID, certificateID string) (VPNServiceTLS, int64, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return VPNServiceTLS{}, 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenantID, nodeID, domain string
	err = tx.QueryRow(ctx, `SELECT tenant_id::text,node_id::text,domain FROM node_certificates WHERE id=$1::uuid AND environment='production' AND status IN ('active','renewing') AND not_before<=now() AND not_after>now() FOR UPDATE`, certificateID).Scan(&tenantID, &nodeID, &domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return VPNServiceTLS{}, 0, ErrVPNServiceTLSInvalid
	}
	if err != nil {
		return VPNServiceTLS{}, 0, err
	}
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT enabled FROM vpn_services WHERE id=$1::uuid AND tenant_id=$2::uuid AND node_id=$3::uuid AND ((protocol IN ('vless','trojan') AND (transport='tcp' OR (transport IN ('xhttp','ws','grpc') AND protocol='vless'))) OR (protocol='hysteria2' AND transport='udp')) AND security='tls' FOR UPDATE`, serviceID, tenantID, nodeID).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return VPNServiceTLS{}, 0, ErrVPNServiceTLSInvalid
	}
	if err != nil {
		return VPNServiceTLS{}, 0, err
	}
	out := VPNServiceTLS{ServiceID: serviceID, CertificateID: certificateID, ServerName: domain}
	tag, err := tx.Exec(ctx, `INSERT INTO vpn_service_tls(service_id,tenant_id,node_id,certificate_id) VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid) ON CONFLICT(service_id) DO UPDATE SET certificate_id=EXCLUDED.certificate_id,updated_at=now() WHERE vpn_service_tls.certificate_id<>EXCLUDED.certificate_id`, serviceID, tenantID, nodeID, certificateID)
	if err != nil {
		return out, 0, err
	}
	var generation int64
	if tag.RowsAffected() > 0 {
		if enabled {
			state, releaseID, err := buildNodeDesiredStateTx(ctx, tx, nodeID)
			if err != nil {
				return out, 0, err
			}
			if err = saveDesiredStateTx(ctx, tx, nodeID, state, releaseID); err != nil {
				return out, 0, err
			}
			generation = state.Generation
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,node_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2::uuid,'vpn_service.tls_configured','admin','control-plane',jsonb_build_object('service_id',$3::text,'certificate_id',$4::text))`, tenantID, nodeID, serviceID, certificateID)
		if err != nil {
			return out, 0, err
		}
	}
	return out, generation, tx.Commit(ctx)
}

func fillServiceTLS(tx pgx.Tx, ctx context.Context, nodeID string, services []model.ServiceSpec) error {
	for i := range services {
		s := &services[i]
		if s.Security != "tls" || s.Protocol == "openvpn" {
			continue
		}
		var spec model.TLSSpec
		err := tx.QueryRow(ctx, `SELECT c.id::text,c.domain FROM vpn_service_tls t JOIN node_certificates c ON c.id=t.certificate_id AND c.node_id=t.node_id AND c.tenant_id=t.tenant_id JOIN nodes n ON n.id=t.node_id
		WHERE t.service_id=$1::uuid AND t.node_id=$2::uuid AND c.environment='production' AND c.status IN ('active','renewing') AND c.not_before<=now() AND c.not_after>now()
		AND string_to_array(n.agent_version,'.')::int[]>=CASE WHEN $3::text='hysteria2' THEN ARRAY[0,2,25] WHEN $4::text IN ('ws','grpc') THEN ARRAY[0,2,26] WHEN $4::text='xhttp' THEN ARRAY[0,2,17] WHEN $3::text='trojan' THEN ARRAY[0,2,16] ELSE ARRAY[0,2,15] END`, s.ID, nodeID, s.Protocol, s.Transport).Scan(&spec.CertificateID, &spec.ServerName)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("service %s requires a valid TLS certificate and compatible agent version", s.ID)
		}
		if err != nil {
			return err
		}
		s.TLS = &spec
	}
	return nil
}
