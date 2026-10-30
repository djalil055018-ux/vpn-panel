package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

var ErrVPNCascade = errors.New("cascade requires distinct compatible Xray nodes, available port and group")
var ErrVPNCascadeIdentity = errors.New("cascade desired state differs from canonical configuration")

type cascadePrivate struct {
	model.VPNCascade
	transit string
}

const cascadeColumns = `id::text,tenant_id::text,name,plan_id::text,entry_service_id::text,exit_service_id::text,entry_node_id::text,exit_node_id::text,entry_port,enabled,created_at,updated_at,connect_race_ip,connect_race_attempts,connect_race_clients`

func scanCascade(row pgx.Row) (model.VPNCascade, error) {
	var c model.VPNCascade
	err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.PlanID, &c.EntryServiceID, &c.ExitServiceID, &c.EntryNodeID, &c.ExitNodeID, &c.EntryPort, &c.Enabled, &c.CreatedAt, &c.UpdatedAt, &c.ConnectRaceIP, &c.ConnectRaceAttempts, &c.ConnectRaceClients)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return c, err
}

func cascadeEndpointTx(ctx context.Context, tx pgx.Tx, serviceID, nodeID string) (model.XrayCascadeEndpoint, error) {
	var e model.XrayCascadeEndpoint
	var protocol, transport, security, agent, runtime string
	var coreRaw []byte
	err := tx.QueryRow(ctx, `SELECT s.protocol,s.transport,s.security,COALESCE(s.public_address,''),COALESCE(s.public_port,0),COALESCE(r.server_name,''),COALESCE(r.public_key,''),COALESCE(r.short_id,''),COALESCE(r.fingerprint,''),COALESCE(n.agent_version,''),n.runtime_core,ds.document->'core'
 FROM vpn_services s JOIN nodes n ON n.id=s.node_id AND n.tenant_id=s.tenant_id
 JOIN desired_states ds ON ds.node_id=n.id AND ds.generation=n.desired_generation
 LEFT JOIN vpn_service_reality r ON r.service_id=s.id AND r.tenant_id=s.tenant_id
 WHERE s.id=$1::uuid AND s.node_id=$2::uuid AND s.enabled AND n.status<>'retired'`, serviceID, nodeID).Scan(&protocol, &transport, &security, &e.Address, &e.Port, &e.ServerName, &e.PublicKey, &e.ShortID, &e.Fingerprint, &agent, &runtime, &coreRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, ErrVPNCascade
	}
	if err != nil {
		return e, err
	}
	var core model.CoreRelease
	if protocol != "vless" || transport != "tcp" || security != "reality" || runtime != "xray" || !model.XrayCascadeAgentCompatible(agent) || json.Unmarshal(coreRaw, &core) != nil || !xrayprofile.CoreCompatible(core) {
		return e, ErrVPNCascade
	}
	profile, status, _, err := registeredXrayProfile(ctx, tx, nodeID)
	if err != nil {
		return e, err
	}
	if profile != nil {
		if status != "active" {
			return e, ErrVPNCascade
		}
		e.Flow, err = xrayprofile.VLESSFlow(profile, serviceID)
		if err != nil {
			return e, ErrVPNCascade
		}
	}
	return e, nil
}

func buildXrayCascadeSpecTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState) (*model.XrayCascadesSpec, error) {
	rows, err := tx.Query(ctx, `SELECT `+cascadeColumns+`,transit_uuid::text FROM vpn_active_cascades WHERE entry_node_id=$1::uuid OR exit_node_id=$1::uuid ORDER BY id`, nodeID)
	if err != nil {
		return nil, err
	}
	definitions := []cascadePrivate{}
	for rows.Next() {
		var c cascadePrivate
		if err = rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.PlanID, &c.EntryServiceID, &c.ExitServiceID, &c.EntryNodeID, &c.ExitNodeID, &c.EntryPort, &c.Enabled, &c.CreatedAt, &c.UpdatedAt, &c.ConnectRaceIP, &c.ConnectRaceAttempts, &c.ConnectRaceClients, &c.transit); err != nil {
			rows.Close()
			return nil, err
		}
		definitions = append(definitions, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(definitions) == 0 {
		return nil, nil
	}
	if !xrayprofile.CoreCompatible(state.Core) {
		return nil, ErrVPNCascade
	}
	var agent string
	if err = tx.QueryRow(ctx, `SELECT COALESCE(agent_version,'') FROM nodes WHERE id=$1::uuid`, nodeID).Scan(&agent); err != nil {
		return nil, err
	}
	if !model.XrayCascadeAgentCompatible(agent) {
		return nil, ErrNodeRuntime
	}
	plan := &model.XrayCascadesSpec{Version: 1}
	for _, c := range definitions {
		var collision bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_services WHERE node_id=$1::uuid AND port=$2)
 OR EXISTS(SELECT 1 FROM vpn_clients WHERE vless_uuid=$3::uuid)`, c.EntryNodeID, c.EntryPort, c.transit).Scan(&collision); err != nil {
			return nil, err
		}
		if collision {
			return nil, ErrVPNCascade
		}
		// Both nodes are checked on every rebuild, including imported core flow.
		entry, err := cascadeEndpointTx(ctx, tx, c.EntryServiceID, c.EntryNodeID)
		if err != nil {
			return nil, err
		}
		entry.ClientID = c.transit
		if !compiler.ValidXrayCascadeEndpoint(entry) {
			return nil, ErrVPNCascade
		}
		exit, err := cascadeEndpointTx(ctx, tx, c.ExitServiceID, c.ExitNodeID)
		if err != nil {
			return nil, err
		}
		exit.ClientID = c.transit
		exit.ConnectRaceIP, exit.ConnectRaceAttempts = c.ConnectRaceIP, c.ConnectRaceAttempts
		if !model.ValidCascadeDial(exit.ConnectRaceIP, exit.ConnectRaceAttempts) {
			return nil, ErrVPNCascade
		}
		if c.EntryNodeID == nodeID && exit.ConnectRaceAttempts > 0 && (!model.CascadeDialAgentCompatible(agent) || !xrayprofile.DialRaceCoreCompatible(state.Core)) {
			return nil, ErrNodeRuntime
		}
		if !compiler.ValidXrayCascadeEndpoint(exit) {
			return nil, ErrVPNCascade
		}
		if c.ExitNodeID == nodeID {
			plan.Exits = append(plan.Exits, model.XrayCascadeExit{ID: c.ID, ServiceID: c.ExitServiceID, ClientID: c.transit})
			continue
		}
		clients := []model.ClientSpec{}
		members, err := tx.Query(ctx, `SELECT c.vless_uuid::text,c.id::text FROM vpn_effective_client_cascades e JOIN vpn_clients c ON c.id=e.client_id AND c.tenant_id=e.tenant_id WHERE e.cascade_id=$1::uuid ORDER BY c.created_at,c.id`, c.ID)
		if err != nil {
			return nil, err
		}
		for members.Next() {
			var client model.ClientSpec
			if err = members.Scan(&client.ID, &client.StatsKey); err != nil {
				members.Close()
				return nil, err
			}
			clients = append(clients, client)
		}
		err = members.Err()
		members.Close()
		if err != nil {
			return nil, err
		}
		plan.Entries = append(plan.Entries, model.XrayCascadeEntry{ID: c.ID, ServiceID: c.EntryServiceID, Port: c.EntryPort, Clients: clients, Exit: exit})
	}
	state.XrayCascades = plan
	if _, err = compiler.XrayAuthorizationConfig(state); err != nil {
		return nil, ErrVPNCascade
	}
	return plan, nil
}

func validateXrayCascadeDesiredTx(ctx context.Context, tx pgx.Tx, nodeID string, state model.DesiredState, release string) error {
	var configured bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_active_cascades WHERE entry_node_id=$1::uuid OR exit_node_id=$1::uuid)`, nodeID).Scan(&configured); err != nil {
		return err
	}
	if !configured && state.XrayCascades == nil {
		return nil
	}
	canonical, _, err := buildNodeDesiredWithBaseTx(ctx, tx, nodeID, state.Generation-1, state, release)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(state.XrayCascades)
	b, _ := json.Marshal(canonical.XrayCascades)
	if !bytes.Equal(a, b) {
		return ErrVPNCascadeIdentity
	}
	if canonical.XrayCascades == nil {
		return nil
	}
	referenced := map[string]bool{}
	for _, entry := range canonical.XrayCascades.Entries {
		referenced[entry.ServiceID] = true
	}
	for _, exit := range canonical.XrayCascades.Exits {
		referenced[exit.ServiceID] = true
	}
	actual := map[string]model.ServiceSpec{}
	for _, service := range state.Services {
		if _, exists := actual[service.ID]; exists {
			return ErrVPNCascadeIdentity
		}
		actual[service.ID] = service
	}
	for _, service := range canonical.Services {
		if !referenced[service.ID] {
			continue
		}
		found, exists := actual[service.ID]
		if !exists {
			return ErrVPNCascadeIdentity
		}
		a, _ := json.Marshal(service)
		b, _ := json.Marshal(found)
		if !bytes.Equal(a, b) {
			return ErrVPNCascadeIdentity
		}
	}
	return nil
}
