package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

func buildNodeDesiredStateTx(
	ctx context.Context,
	tx pgx.Tx,
	nodeID string,
) (
	model.DesiredState,
	string,
	error,
) {
	var currentGeneration int64
	var raw []byte
	var coreReleaseID string

	err :=
		tx.QueryRow(
			ctx,
			`
			SELECT
				n.desired_generation,
				ds.document,
				d.core_release_id::text
			FROM nodes n
			JOIN desired_states ds
				ON ds.node_id = n.id
				AND ds.generation =
					n.desired_generation
			JOIN deployments d
				ON d.node_id = n.id
				AND d.generation =
					n.desired_generation
			WHERE n.id = $1::uuid
			FOR UPDATE OF n
			`,
			nodeID,
		).Scan(
			&currentGeneration,
			&raw,
			&coreReleaseID,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.DesiredState{},
			"",
			ErrNotFound
	}

	if err != nil {
		return model.DesiredState{},
			"",
			err
	}

	var current model.DesiredState

	if err :=
		json.Unmarshal(
			raw,
			&current,
		); err != nil {

		return model.DesiredState{},
			"",
			fmt.Errorf(
				"decode current desired state: %w",
				err,
			)
	}

	return buildNodeDesiredWithBaseTx(ctx, tx, nodeID, currentGeneration, current, coreReleaseID)
}

// The caller holds the node and tenant access locks. An adoption transaction can
// supply an approved core at generation zero, so its first saved document already
// contains the complete registered profile and current native authorization.
// No empty intermediate deployment has to be published to initialize the node.
func buildNodeDesiredWithBaseTx(ctx context.Context, tx pgx.Tx, nodeID string, currentGeneration int64, current model.DesiredState, coreReleaseID string) (model.DesiredState, string, error) {
	profile, profileState, _, err := registeredXrayProfile(ctx, tx, nodeID)
	if err != nil {
		return model.DesiredState{}, "", err
	}
	if profile != nil && profileState == "active" {
		if current.XrayProfile != nil && current.XrayProfile.SHA256 != profile.SHA256 {
			return model.DesiredState{}, "", ErrXrayProfileIdentity
		}
		current.XrayProfile = profile
	} else if current.XrayProfile != nil {
		return model.DesiredState{}, "", ErrXrayProfileHeld
	}

	serviceRows, err :=
		tx.Query(
			ctx,
			`
			SELECT
				s.id::text,
				s.protocol,
				s.listen,
				s.port,
				s.transport,
				s.security,

				COALESCE(
					r.destination,
					''
				),

				COALESCE(
					r.server_name,
					''
				),

				COALESCE(
					r.fingerprint,
					''
				),

				COALESCE(
					r.short_id,
					''
				),

				COALESCE(
					r.secret_ref,
					''
				)

			FROM vpn_services s

			LEFT JOIN vpn_service_reality r
				ON r.service_id = s.id
				AND r.tenant_id = s.tenant_id

			WHERE s.node_id = $1::uuid
			  AND s.enabled = true

			ORDER BY
				s.created_at ASC,
				s.id ASC
			`,
			nodeID,
		)

	if err != nil {
		return model.DesiredState{},
			"",
			err
	}

	services :=
		make(
			[]model.ServiceSpec,
			0,
		)

	for serviceRows.Next() {
		var service model.ServiceSpec

		var destination string
		var serverName string
		var fingerprint string
		var shortID string
		var secretRef string

		if err :=
			serviceRows.Scan(
				&service.ID,
				&service.Protocol,
				&service.Listen,
				&service.Port,
				&service.Transport,
				&service.Security,
				&destination,
				&serverName,
				&fingerprint,
				&shortID,
				&secretRef,
			); err != nil {

			serviceRows.Close()

			return model.DesiredState{},
				"",
				err
		}

		isHysteria := current.Core.Type == "hysteria2" && service.Protocol == "hysteria2" && service.Transport == "udp" && service.Security == "tls"
		isShadowsocks := current.Core.Type == "xray" && service.Protocol == "shadowsocks" && service.Transport == "tcp,udp" && service.Security == "shadowsocks"
		isWireGuard := (current.Core.Type == "xray" || current.Core.Type == "wireguard") && service.Protocol == "wireguard" && service.Transport == "udp" && service.Security == "wireguard"
		isOpenVPN := current.Core.Type == "openvpn" && service.Protocol == "openvpn" && (service.Transport == "udp" || service.Transport == "tcp") && service.Security == "tls"
		isPPTP := current.Core.Type == "pptp" && service.Protocol == "pptp" && service.Transport == "tcp,gre" && service.Security == "mppe"
		if current.XrayProfile == nil && !isPPTP && !isHysteria && !isShadowsocks && !isWireGuard && !isOpenVPN && ((service.Protocol != "vless" && service.Protocol != "trojan") ||
			(service.Transport != "tcp" && !(model.VLESSTLSTransport(service.Transport) && service.Protocol == "vless" && service.Security == "tls")) ||
			(service.Security != "reality" && service.Security != "tls")) {

			serviceRows.Close()

			return model.DesiredState{},
				"",
				fmt.Errorf(
					"enabled service %s is not an approved service",
					service.ID,
				)
		}

		if service.Protocol == "trojan" && service.Security != "tls" {
			serviceRows.Close()
			return model.DesiredState{}, "", fmt.Errorf("Trojan requires TLS")
		}
		if service.Security == "tls" || isShadowsocks || isWireGuard || isPPTP {
			services = append(services, service)
			continue
		}

		if destination == "" ||
			serverName == "" ||
			fingerprint == "" ||
			(shortID == "" && current.XrayProfile == nil) ||
			secretRef == "" {

			serviceRows.Close()

			return model.DesiredState{},
				"",
				fmt.Errorf(
					"incomplete reality configuration for service %s",
					service.ID,
				)
		}

		service.Reality =
			&model.RealitySpec{
				Destination: destination,

				ServerName: serverName,

				Fingerprint: fingerprint,

				ShortID: shortID,

				SecretRef: secretRef,
			}

		services =
			append(
				services,
				service,
			)
	}

	if err := serviceRows.Err(); err != nil {
		serviceRows.Close()

		return model.DesiredState{},
			"",
			err
	}

	// Important: pgx cannot execute another query on this
	// transaction while serviceRows is still open.
	serviceRows.Close()
	for _, service := range services {
		if service.Transport == "xhttp" && !xhttpCoreCompatible(current.Core) {
			return model.DesiredState{}, "", fmt.Errorf("XHTTP requires Xray 26.7.28 or newer")
		}
	}
	if err := fillServiceTLS(tx, ctx, nodeID, services); err != nil {
		return model.DesiredState{}, "", err
	}

	for i := range services {

		clientRows, err :=
			tx.Query(
				ctx,
				`
				SELECT
					c.vless_uuid::text,
					c.id::text

				FROM vpn_effective_client_services cs

				JOIN vpn_clients c
					ON c.id = cs.client_id
					AND c.tenant_id =
						cs.tenant_id

				WHERE cs.service_id =
					$1::uuid

				  AND c.status = 'active'

				  AND (
					c.expires_at IS NULL
					OR c.expires_at > now()
				  )

				  AND NOT vpn_client_quota_exceeded(c.id)

				ORDER BY
					c.created_at ASC,
					c.id ASC
				`,
				services[i].ID,
			)

		if err != nil {
			return model.DesiredState{},
				"",
				err
		}

		clients :=
			make(
				[]model.ClientSpec,
				0,
			)

		for clientRows.Next() {
			var client model.ClientSpec

			if err :=
				clientRows.Scan(
					&client.ID,
					&client.StatsKey,
				); err != nil {

				clientRows.Close()

				return model.DesiredState{},
					"",
					err
			}

			clients =
				append(
					clients,
					client,
				)
		}

		if err :=
			clientRows.Err(); err != nil {

			clientRows.Close()

			return model.DesiredState{},
				"",
				err
		}

		clientRows.Close()

		services[i].Clients =
			clients
	}

	if err := fillShadowsocksKeysTx(ctx, tx, services); err != nil {
		return model.DesiredState{}, "", err
	}
	if err := fillWireGuardKeysTx(ctx, tx, services); err != nil {
		return model.DesiredState{}, "", err
	}
	if err := fillPPTPKeysTx(ctx, tx, services); err != nil {
		return model.DesiredState{}, "", err
	}
	if err := fillOpenVPNPKITx(ctx, tx, services); err != nil {
		return model.DesiredState{}, "", err
	}
	state :=
		model.DesiredState{
			Generation: currentGeneration + 1,

			Core: current.Core,

			Services:    services,
			XrayProfile: current.XrayProfile,
		}
	if state.XrayProfile != nil {
		if err := xrayprofile.ValidateServices(state.XrayProfile, state.Services); err != nil {
			return model.DesiredState{}, "", err
		}
	}

	state.XrayCascades, err = buildXrayCascadeSpecTx(ctx, tx, nodeID, state)
	if err != nil {
		return model.DesiredState{}, "", err
	}
	return state,
		coreReleaseID,
		nil
}

func (p *Postgres) RebuildNodeDesiredState(
	ctx context.Context,
	nodeID string,
) (
	model.DesiredState,
	error,
) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.DesiredState{}, err
	}
	defer tx.Rollback(ctx)

	state, coreReleaseID, err :=
		buildNodeDesiredStateTx(
			ctx,
			tx,
			nodeID,
		)
	if err != nil {
		return model.DesiredState{}, err
	}

	if err := saveDesiredStateTx(
		ctx,
		tx,
		nodeID,
		state,
		coreReleaseID,
	); err != nil {
		return model.DesiredState{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.DesiredState{}, err
	}

	return state, nil
}

func (p *Postgres) SetVPNServiceEnabledAndRebuild(
	ctx context.Context,
	serviceID string,
	enabled bool,
) (
	model.DesiredState,
	error,
) {
	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.DesiredState{},
			err
	}

	defer tx.Rollback(ctx)

	var nodeID string
	var security string
	var protocol string

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT
				node_id::text,
				security, protocol
			FROM vpn_services
			WHERE id = $1::uuid
			FOR UPDATE
			`,
			serviceID,
		).Scan(
			&nodeID,
			&security,
			&protocol,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.DesiredState{},
			ErrNotFound
	}

	if err != nil {
		return model.DesiredState{},
			err
	}

	if enabled &&
		security != "reality" && security != "tls" && !(protocol == "shadowsocks" && security == "shadowsocks") && !(protocol == "wireguard" && security == "wireguard") && !(protocol == "pptp" && security == "mppe") {

		return model.DesiredState{},
			fmt.Errorf(
				"only reality or TLS services can be enabled",
			)
	}

	if enabled && security == "reality" {
		var realityExists bool

		err =
			tx.QueryRow(
				ctx,
				`
				SELECT EXISTS(
					SELECT 1
					FROM vpn_service_reality
					WHERE service_id =
						$1::uuid
				)
				`,
				serviceID,
			).Scan(
				&realityExists,
			)

		if err != nil {
			return model.DesiredState{},
				err
		}

		if !realityExists {
			return model.DesiredState{},
				fmt.Errorf(
					"reality configuration is missing",
				)
		}
	}

	_, err =
		tx.Exec(
			ctx,
			`
			UPDATE vpn_services
			SET
				enabled = $2,
				updated_at = now()
			WHERE id = $1::uuid
			`,
			serviceID,
			enabled,
		)

	if err != nil {
		return model.DesiredState{},
			err
	}

	state,
		coreReleaseID,
		err :=
		buildNodeDesiredStateTx(
			ctx,
			tx,
			nodeID,
		)

	if err != nil {
		return model.DesiredState{},
			err
	}

	if err :=
		saveDesiredStateTx(
			ctx,
			tx,
			nodeID,
			state,
			coreReleaseID,
		); err != nil {

		return model.DesiredState{},
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return model.DesiredState{},
			err
	}

	return state, nil
}

func (p *Postgres) AttachVPNClientAndRebuild(
	ctx context.Context,
	serviceID string,
	clientID string,
) (
	model.DesiredState,
	error,
) {
	tx, err :=
		p.Pool.Begin(ctx)

	if err != nil {
		return model.DesiredState{},
			err
	}

	defer tx.Rollback(ctx)

	var nodeID string

	err =
		tx.QueryRow(
			ctx,
			`
			SELECT
				s.node_id::text

			FROM vpn_services s

			JOIN vpn_clients c
				ON c.id = $2::uuid
				AND c.tenant_id =
					s.tenant_id

			WHERE s.id = $1::uuid
			  AND s.enabled = true
			  AND ((s.protocol IN ('vless','trojan') AND (s.transport='tcp' OR (s.transport IN ('xhttp','ws','grpc') AND s.protocol='vless' AND s.security='tls')))
			    OR (s.protocol='hysteria2' AND s.transport='udp' AND s.security='tls') OR (s.protocol='shadowsocks' AND s.transport='tcp,udp' AND s.security='shadowsocks') OR (s.protocol='wireguard' AND s.transport='udp' AND s.security='wireguard') OR (s.protocol='openvpn' AND s.transport IN ('tcp','udp') AND s.security='tls') OR (s.protocol='pptp' AND s.transport='tcp,gre' AND s.security='mppe')
			    OR EXISTS(SELECT 1 FROM node_xray_profile_bindings b JOIN node_xray_profiles p USING(node_id,tenant_id)
			      WHERE b.service_id=s.id AND b.node_id=s.node_id AND b.tenant_id=s.tenant_id AND p.state='active'))
			  AND s.security IN ('reality','tls','shadowsocks','wireguard','mppe')

			  AND c.status = 'active'

			  AND (
				c.expires_at IS NULL
				OR c.expires_at > now()
			  )

			FOR UPDATE OF s, c
			`,
			serviceID,
			clientID,
		).Scan(
			&nodeID,
		)

	if errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return model.DesiredState{},
			ErrNotFound
	}

	if err != nil {
		return model.DesiredState{},
			err
	}

	_, err =
		tx.Exec(
			ctx,
			`
			INSERT INTO vpn_client_services(
				tenant_id,
				client_id,
				service_id
			)

			SELECT
				s.tenant_id,
				c.id,
				s.id

			FROM vpn_services s

			JOIN vpn_clients c
				ON c.id = $2::uuid
				AND c.tenant_id =
					s.tenant_id

			WHERE s.id = $1::uuid

			ON CONFLICT (
				client_id,
				service_id
			)
			DO NOTHING
			`,
			serviceID,
			clientID,
		)

	if err != nil {
		return model.DesiredState{},
			err
	}

	state,
		coreReleaseID,
		err :=
		buildNodeDesiredStateTx(
			ctx,
			tx,
			nodeID,
		)

	if err != nil {
		return model.DesiredState{},
			err
	}

	if err :=
		saveDesiredStateTx(
			ctx,
			tx,
			nodeID,
			state,
			coreReleaseID,
		); err != nil {

		return model.DesiredState{},
			err
	}

	if err :=
		tx.Commit(ctx); err != nil {

		return model.DesiredState{},
			err
	}

	return state, nil
}

func (p *Postgres) DetachVPNClientAndRebuild(
	ctx context.Context,
	serviceID string,
	clientID string,
) (
	model.DesiredState,
	error,
) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.DesiredState{}, err
	}
	defer tx.Rollback(ctx)

	var nodeID string

	err = tx.QueryRow(
		ctx,
		`
		SELECT
			s.node_id::text
		FROM vpn_services s
		JOIN vpn_clients c
			ON c.id = $2::uuid
			AND c.tenant_id = s.tenant_id
		JOIN vpn_client_services membership
			ON membership.service_id = s.id
			AND membership.client_id = c.id
			AND membership.tenant_id = s.tenant_id
		WHERE s.id = $1::uuid
		FOR UPDATE OF s, c, membership
		`,
		serviceID,
		clientID,
	).Scan(&nodeID)

	if errors.Is(err, pgx.ErrNoRows) {
		return model.DesiredState{}, ErrNotFound
	}
	if err != nil {
		return model.DesiredState{}, err
	}

	tag, err := tx.Exec(
		ctx,
		`
		DELETE FROM vpn_client_services
		WHERE service_id = $1::uuid
		  AND client_id = $2::uuid
		`,
		serviceID,
		clientID,
	)
	if err != nil {
		return model.DesiredState{}, err
	}

	if tag.RowsAffected() != 1 {
		return model.DesiredState{}, ErrNotFound
	}

	state, coreReleaseID, err :=
		buildNodeDesiredStateTx(
			ctx,
			tx,
			nodeID,
		)
	if err != nil {
		return model.DesiredState{}, err
	}

	if err :=
		saveDesiredStateTx(
			ctx,
			tx,
			nodeID,
			state,
			coreReleaseID,
		); err != nil {
		return model.DesiredState{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return model.DesiredState{}, err
	}

	return state, nil
}
