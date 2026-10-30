package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
	"vpn-platform/internal/model"
)

func (p *Postgres) VPNCascadeStatus(ctx context.Context, id string) (model.VPNCascadeView, error) {
	out := model.VPNCascadeView{State: "pending"}
	var entryStatus, exitStatus, entryDeployment, exitDeployment string
	var active, compiled bool
	err := p.Pool.QueryRow(ctx, `SELECT k.`+strings.ReplaceAll(cascadeColumns, ",", ",k.")+`,n.name,x.name,g.name,COALESCE(n.agent_version,''),COALESCE(x.agent_version,''),n.desired_generation,n.applied_generation,x.desired_generation,x.applied_generation,n.status,x.status,COALESCE(nd.status,''),COALESCE(xd.status,''),EXISTS(SELECT 1 FROM vpn_active_cascades a WHERE a.id=k.id),
 EXISTS(SELECT 1 FROM desired_states ds,jsonb_array_elements(COALESCE(ds.document->'xray_cascades'->'entries','[]'::jsonb)) ce WHERE ds.node_id=n.id AND ds.generation=n.desired_generation AND ce->>'id'=k.id::text)
 AND EXISTS(SELECT 1 FROM desired_states ds,jsonb_array_elements(COALESCE(ds.document->'xray_cascades'->'exits','[]'::jsonb)) ce WHERE ds.node_id=x.id AND ds.generation=x.desired_generation AND ce->>'id'=k.id::text)
 FROM vpn_cascades k JOIN nodes n ON n.id=k.entry_node_id JOIN nodes x ON x.id=k.exit_node_id JOIN vpn_access_plans g ON g.id=k.plan_id
 LEFT JOIN deployments nd ON nd.node_id=n.id AND nd.generation=n.desired_generation
 LEFT JOIN deployments xd ON xd.node_id=x.id AND xd.generation=x.desired_generation WHERE k.id=$1::uuid`, id).Scan(&out.ID, &out.TenantID, &out.Name, &out.PlanID, &out.EntryServiceID, &out.ExitServiceID, &out.EntryNodeID, &out.ExitNodeID, &out.EntryPort, &out.Enabled, &out.CreatedAt, &out.UpdatedAt, &out.ConnectRaceIP, &out.ConnectRaceAttempts, &out.ConnectRaceClients, &out.EntryNodeName, &out.ExitNodeName, &out.PlanName, &out.EntryAgentVersion, &out.ExitAgentVersion, &out.EntryDesiredGeneration, &out.EntryAppliedGeneration, &out.ExitDesiredGeneration, &out.ExitAppliedGeneration, &entryStatus, &exitStatus, &entryDeployment, &exitDeployment, &active, &compiled)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.VPNCascadeView{}, ErrNotFound
	}
	if err != nil {
		return model.VPNCascadeView{}, err
	}
	if !tenantScopeAllowed(ctx, out.TenantID) {
		return model.VPNCascadeView{}, ErrNotFound
	}
	switch {
	case !out.Enabled:
		out.State = "disabled"
	case !active:
		out.State = "inactive"
	case !model.XrayCascadeAgentCompatible(out.EntryAgentVersion) || !model.XrayCascadeAgentCompatible(out.ExitAgentVersion) || (out.ConnectRaceAttempts > 0 && !model.CascadeDialAgentCompatible(out.EntryAgentVersion)):
		out.State = "agent_update_required"
	case entryStatus != "online" || exitStatus != "online":
		out.State = "offline"
	case entryDeployment == "failed" || exitDeployment == "failed":
		out.State = "failed"
	case compiled && entryDeployment == "healthy" && exitDeployment == "healthy" && out.EntryDesiredGeneration == out.EntryAppliedGeneration && out.ExitDesiredGeneration == out.ExitAppliedGeneration:
		out.State = "active"
	}
	return out, nil
}
