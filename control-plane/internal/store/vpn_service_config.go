package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"vpn-platform/internal/model"
)

var ErrVPNServiceBindConflict = errors.New("vpn service listener is already in use")
var ErrVPNServiceFixedPort = errors.New("vpn service uses a fixed listener port")
var ErrVPNServiceTransportImmutable = errors.New("transport is managed by a protocol-specific configuration")
var ErrVPNServiceTransportInvalid = errors.New("invalid transport for protocol and security")
var ErrVPNServiceAgentIncompatible = errors.New("selected VLESS transport requires a newer node agent")

func requiredAgentForVLESSTLSTransport(transport string) string {
	switch transport {
	case "xhttp":
		return "0.2.17"
	case "ws", "grpc":
		return "0.2.26"
	case "tcp":
		return "0.2.15"
	default:
		return ""
	}
}

func validateVPNServiceTransport(protocol, security, current, requested string) error {
	if requested == "" || requested == current {
		return nil
	}
	if protocol == "openvpn" {
		if requested == "tcp" || requested == "udp" {
			return nil
		}
		return ErrVPNServiceTransportInvalid
	}
	if protocol == "vless" && security == "tls" && model.VLESSTLSTransport(requested) {
		return nil
	}
	if protocol == "vless" && security == "tls" {
		return ErrVPNServiceTransportInvalid
	}
	return ErrVPNServiceTransportImmutable
}

// UpdateVPNServiceConfigurationAndRebuild changes the service endpoint and
// listener atomically with the desired generation delivered to its node.
func (p *Postgres) UpdateVPNServiceConfigurationAndRebuild(
	ctx context.Context,
	serviceID string,
	name string,
	listen string,
	port int,
	transport string,
	publicAddress string,
	publicPort int,
) (model.VPNService, model.DesiredState, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))

	var tenant string
	if err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM vpn_services WHERE id=$1::uuid`, serviceID).Scan(&tenant); errors.Is(err, pgx.ErrNoRows) {
		return model.VPNService{}, model.DesiredState{}, ErrNotFound
	} else if err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	if !tenantScopeAllowed(ctx, tenant) {
		return model.VPNService{}, model.DesiredState{}, ErrNotFound
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	var previousPublicAddress string
	var nodeID string
	var protocol string
	var security string
	var currentTransport string
	var nodeStatus string
	var agentVersion string
	err = tx.QueryRow(ctx, `
		SELECT s.node_id::text, s.protocol, s.security, s.transport, n.status, COALESCE(n.agent_version,''),COALESCE(s.public_address,'')
		FROM vpn_services s
		JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
		WHERE s.id=$1::uuid
		FOR UPDATE OF s,n`, serviceID).Scan(&nodeID, &protocol, &security, &currentTransport, &nodeStatus, &agentVersion, &previousPublicAddress)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNService{}, model.DesiredState{}, ErrNotFound
	}
	if err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	if nodeStatus == "retired" {
		return model.VPNService{}, model.DesiredState{}, ErrNodeRetired
	}
	if protocol == "pptp" && port != 1723 {
		return model.VPNService{}, model.DesiredState{}, ErrVPNServiceFixedPort
	}
	if err := validateVPNServiceTransport(protocol, security, currentTransport, transport); err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	if transport == "" {
		transport = currentTransport
	}
	if protocol == "vless" && security == "tls" && transport != currentTransport {
		requiredAgent := requiredAgentForVLESSTLSTransport(transport)
		if requiredAgent != "" {
			var compatible bool
			if err := tx.QueryRow(ctx, `SELECT COALESCE(agent_version_rank($1::text) >= agent_version_rank($2::text),false)`, agentVersion, requiredAgent).Scan(&compatible); err != nil {
				return model.VPNService{}, model.DesiredState{}, err
			}
			if !compatible {
				return model.VPNService{}, model.DesiredState{}, ErrVPNServiceAgentIncompatible
			}
		}
	}

	service, err := scanVPNService(tx.QueryRow(ctx, `
		UPDATE vpn_services
		SET name=CASE WHEN $2::text='' THEN name ELSE $2::text END,
		    listen=$3, port=$4, transport=$5, public_address=$6, public_port=$7, updated_at=now()
		WHERE id=$1::uuid
		RETURNING id::text,tenant_id::text,node_id::text,name,protocol,listen,port,transport,security,
		          public_address,public_port,enabled,created_at,updated_at,subscription_name`,
		serviceID, name, listen, port, transport, publicAddress, publicPort))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && (pgErr.ConstraintName == "vpn_services_bind_unique" || pgErr.ConstraintName == "vpn_services_tcp_bind_unique" || pgErr.ConstraintName == "vpn_services_udp_bind_unique") {
			return model.VPNService{}, model.DesiredState{}, ErrVPNServiceBindConflict
		}
		return model.VPNService{}, model.DesiredState{}, err
	}

	if previousPublicAddress != publicAddress {
		tag, e := tx.Exec(ctx, `UPDATE vpn_cascades SET connect_race_ip='',connect_race_attempts=0,connect_race_clients=false,updated_at=now() WHERE exit_service_id=$1::uuid AND connect_race_attempts>0`, serviceID)
		if e != nil {
			return model.VPNService{}, model.DesiredState{}, e
		}
		if tag.RowsAffected() > 0 {
			actor, actorID := accessActor(ctx)
			if _, e = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'vpn_cascade.connect_policy_cleared',$2,$3,jsonb_build_object('service_id',$4::text,'count',$5::integer))`, tenant, actor, actorID, serviceID, tag.RowsAffected()); e != nil {
				return model.VPNService{}, model.DesiredState{}, e
			}
		}
	}
	state, coreReleaseID, err := buildNodeDesiredStateTx(ctx, tx, nodeID)
	if err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	if err := saveDesiredStateTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	// Endpoint changes must reach the entry as well as the exit. Otherwise a
	// cascade can continue dialing an older public address until another mutation.
	rows, e := tx.Query(ctx, `SELECT DISTINCT entry_node_id::text FROM vpn_active_cascades WHERE exit_service_id=$1::uuid AND entry_node_id<>$2::uuid ORDER BY entry_node_id::text`, serviceID, nodeID)
	if e != nil {
		return model.VPNService{}, model.DesiredState{}, e
	}
	related := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return model.VPNService{}, model.DesiredState{}, e
		}
		related = append(related, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return model.VPNService{}, model.DesiredState{}, e
	}
	if len(related) > 0 {
		if _, e = rebuildCascadeNodesTx(ctx, tx, related); e != nil {
			return model.VPNService{}, model.DesiredState{}, e
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}

	return service, state, nil
}
