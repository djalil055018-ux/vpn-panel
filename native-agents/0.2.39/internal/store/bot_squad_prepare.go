package store

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type BotSquadPlan struct {
	SourceSquadID string `json:"source_squad_id"`
	PlanID        string `json:"plan_id"`
	Services      int    `json:"services"`
}
type BotSquadPreparation struct {
	RevisionID      string         `json:"revision_id"`
	InventorySHA256 string         `json:"inventory_sha256"`
	BundleSHA256    string         `json:"bundle_sha256"`
	State           string         `json:"state"`
	Plans           []BotSquadPlan `json:"plans"`
}

// PrepareBotSquadPlans binds disabled native plans to the exact reviewed public
// revision. Preparation never activates bot membership or any native service.
// Existing independently edited plans are rejected, never silently repaired.
func (p *Postgres) PrepareBotSquadPlans(ctx context.Context, tenant, importID, inventorySHA, revisionID, bundleSHA string) (out BotSquadPreparation, err error) {
	if !remnawaveOwnerAllowed(ctx) {
		return out, ErrNotFound
	}
	for _, id := range []string{tenant, importID, revisionID} {
		if !xrayPreparationUUID.MatchString(id) {
			return out, ErrBotBridgeRequest
		}
	}
	for _, sha := range []string{inventorySHA, bundleSHA} {
		if !xrayPreparationDigest.MatchString(sha) {
			return out, ErrRemnawaveReview
		}
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	defer func() {
		var e *pgconn.PgError
		if errors.As(err, &e) && (e.Code == "23505" || e.Code == "23503") {
			err = ErrBotBridgeConflict
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
	var currentSHA string
	if err = tx.QueryRow(ctx, `SELECT inventory_sha256 FROM remnawave_import_heads WHERE import_id=$1::uuid FOR UPDATE`, importID).Scan(&currentSHA); err != nil {
		return out, err
	}
	if currentSHA != inventorySHA {
		return out, ErrRemnawaveReview
	}
	var profileImport, profileSHA, profileState string
	err = tx.QueryRow(ctx, `SELECT import_id::text,inventory_sha256,state FROM bot_profiles WHERE tenant_id=$1::uuid FOR UPDATE`, tenant).Scan(&profileImport, &profileSHA, &profileState)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrBotBridgeHeld
	}
	if err != nil {
		return out, err
	}
	if profileImport != importID || profileSHA != inventorySHA || profileState != "held" {
		return out, ErrBotBridgeHeld
	}
	var publicImport, publicRevision, publicState, publicInventory, publicBundle string
	err = tx.QueryRow(ctx, `SELECT h.import_id::text,h.revision_id::text,h.state,r.inventory_sha256,r.bundle_sha256
 FROM imported_subscription_profiles h JOIN imported_subscription_revisions r ON r.id=h.revision_id AND r.tenant_id=h.tenant_id
 WHERE h.tenant_id=$1::uuid FOR UPDATE OF h`, tenant).Scan(&publicImport, &publicRevision, &publicState, &publicInventory, &publicBundle)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrImportedSubscriptionHeld
	}
	if err != nil {
		return out, err
	}
	if publicImport != importID || publicRevision != revisionID || publicInventory != inventorySHA || publicBundle != bundleSHA {
		return out, ErrRemnawaveReview
	}
	if publicState != "prepared" {
		return out, ErrImportedSubscriptionHeld
	}
	var changed bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remnawave_import_clients m JOIN vpn_clients c ON c.id=m.client_id
 WHERE m.import_id=$1::uuid AND (c.tenant_id<>$2::uuid OR NOT c.remnawave_hold OR c.status<>'disabled'
 OR EXISTS(SELECT 1 FROM node_client_traffic_cursors x WHERE x.client_id=c.id)))
 OR EXISTS(SELECT 1 FROM node_xray_profiles p JOIN nodes n ON n.id=p.node_id WHERE p.import_id=$1::uuid AND (p.state<>'prepared' OR n.desired_generation<>0))
 OR EXISTS(SELECT 1 FROM imported_subscription_squad_services x JOIN vpn_services s ON s.id=x.service_id
 LEFT JOIN node_xray_profiles p ON p.node_id=s.node_id WHERE x.revision_id=$3::uuid AND (s.enabled OR p.import_id IS DISTINCT FROM $1::uuid OR p.state IS DISTINCT FROM 'prepared'))`, importID, tenant, revisionID).Scan(&changed)
	if err != nil {
		return out, err
	}
	if changed {
		return out, ErrBotBridgeConflict
	}
	type squad struct {
		id, name string
		plan     *string
	}
	squads := []squad{}
	rows, err := tx.Query(ctx, `SELECT source_uuid::text,name,plan_id::text FROM bot_squads WHERE tenant_id=$1::uuid AND source_present ORDER BY source_uuid FOR UPDATE`, tenant)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var s squad
		if err = rows.Scan(&s.id, &s.name, &s.plan); err != nil {
			rows.Close()
			return out, err
		}
		squads = append(squads, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	out = BotSquadPreparation{RevisionID: revisionID, InventorySHA256: inventorySHA, BundleSHA256: bundleSHA, State: "held", Plans: []BotSquadPlan{}}
	created := 0
	for _, s := range squads {
		name, code := "Remnawave: "+s.name, "remna-"+strings.ReplaceAll(s.id, "-", "")
		var expected []string
		err = tx.QueryRow(ctx, `SELECT coalesce(array_agg(service_id::text ORDER BY service_id),ARRAY[]::text[]) FROM imported_subscription_squad_services WHERE revision_id=$1::uuid AND tenant_id=$2::uuid AND source_squad_id=$3::uuid`, revisionID, tenant, s.id).Scan(&expected)
		if err != nil {
			return out, err
		}
		var id string
		if s.plan == nil {
			if err = checkTenantQuota(ctx, tx, tenant, "plan"); err != nil {
				return out, err
			}
			if err = tx.QueryRow(ctx, `INSERT INTO vpn_access_plans(tenant_id,name,code,enabled) VALUES($1::uuid,$2,$3,false) RETURNING id::text`, tenant, name, code).Scan(&id); err != nil {
				return out, err
			}
			for _, service := range expected {
				if _, err = tx.Exec(ctx, `INSERT INTO vpn_access_plan_services(tenant_id,plan_id,service_id) VALUES($1::uuid,$2::uuid,$3::uuid)`, tenant, id, service); err != nil {
					return out, err
				}
			}
			if _, err = tx.Exec(ctx, `UPDATE bot_squads SET plan_id=$3::uuid WHERE tenant_id=$1::uuid AND source_uuid=$2::uuid`, tenant, s.id, id); err != nil {
				return out, err
			}
			created++
		} else {
			id = *s.plan
			var oldName, oldCode string
			var enabled bool
			err = tx.QueryRow(ctx, `SELECT name,code,enabled FROM vpn_access_plans WHERE id=$1::uuid AND tenant_id=$2::uuid FOR UPDATE`, id, tenant).Scan(&oldName, &oldCode, &enabled)
			if errors.Is(err, pgx.ErrNoRows) {
				return out, ErrBotBridgeConflict
			}
			if err != nil {
				return out, err
			}
			if oldName != name || oldCode != code || enabled {
				return out, ErrBotBridgeConflict
			}
			var actual []string
			if err = tx.QueryRow(ctx, `SELECT coalesce(array_agg(service_id::text ORDER BY service_id),ARRAY[]::text[]) FROM vpn_access_plan_services WHERE plan_id=$1::uuid AND tenant_id=$2::uuid`, id, tenant).Scan(&actual); err != nil {
				return out, err
			}
			if !reflect.DeepEqual(actual, expected) {
				return out, ErrBotBridgeConflict
			}
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM vpn_client_access_plans WHERE plan_id=$1::uuid) OR EXISTS(SELECT 1 FROM billing_entitlements WHERE plan_id=$1::uuid) OR EXISTS(SELECT 1 FROM billing_invoices WHERE plan_id=$1::uuid) OR EXISTS(SELECT 1 FROM billing_offers WHERE plan_id=$1::uuid)`, id).Scan(&changed); err != nil {
				return out, err
			}
			if changed {
				return out, ErrBotBridgeConflict
			}
		}
		out.Plans = append(out.Plans, BotSquadPlan{SourceSquadID: s.id, PlanID: id, Services: len(expected)})
	}
	if created > 0 {
		actor, actorID := accessActor(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'bot_squads.prepared',$2,$3,jsonb_build_object('import_id',$4::text,'revision_id',$5::text,'inventory_sha256',$6::text,'bundle_sha256',$7::text,'plans',$8::integer,'state','held'))`, tenant, actor, actorID, importID, revisionID, inventorySHA, bundleSHA, created)
		if err != nil {
			return out, err
		}
	}
	return out, tx.Commit(ctx)
}
