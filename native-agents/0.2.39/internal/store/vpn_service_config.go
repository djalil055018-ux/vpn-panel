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
var ErrVPNServiceTransportImmutable = errors.New("transport can only be changed for OpenVPN")
var ErrVPNServiceTransportInvalid = errors.New("invalid OpenVPN transport")

func validateVPNServiceTransport(protocol, current, requested string) error {
	if requested == "" || requested == current {
		return nil
	}
	if protocol != "openvpn" {
		return ErrVPNServiceTransportImmutable
	}
	if requested != "tcp" && requested != "udp" {
		return ErrVPNServiceTransportInvalid
	}
	return nil
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

	var nodeID string
	var protocol string
	var currentTransport string
	var nodeStatus string
	err = tx.QueryRow(ctx, `
		SELECT s.node_id::text, s.protocol, s.transport, n.status
		FROM vpn_services s
		JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
		WHERE s.id=$1::uuid
		FOR UPDATE OF s,n`, serviceID).Scan(&nodeID, &protocol, &currentTransport, &nodeStatus)
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
	if err := validateVPNServiceTransport(protocol, currentTransport, transport); err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	if transport == "" {
		transport = currentTransport
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

	state, coreReleaseID, err := buildNodeDesiredStateTx(ctx, tx, nodeID)
	if err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	if err := saveDesiredStateTx(ctx, tx, nodeID, state, coreReleaseID); err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.VPNService{}, model.DesiredState{}, err
	}

	return service, state, nil
}
