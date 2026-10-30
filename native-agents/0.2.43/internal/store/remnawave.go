package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"vpn-platform/internal/remnawave"
)

var ErrRemnawaveConflict = errors.New("Remnawave source or client identity conflicts with existing data")
var ErrRemnawaveHold = errors.New("Remnawave client is held pending reviewed migration cutover")
var ErrRemnawaveReview = errors.New("reviewed inventory digest does not match uploaded bytes")

type RemnawaveImport struct {
	ID        string           `json:"id"`
	TenantID  string           `json:"tenant_id"`
	State     string           `json:"state"`
	CreatedAt time.Time        `json:"created_at"`
	Report    remnawave.Report `json:"report"`
}
type RemnawaveImportClient struct {
	SourceID      int64  `json:"source_user_id"`
	SourceStatus  string `json:"source_status"`
	ClientID      string `json:"client_id"`
	Name          string `json:"name"`
	Held          bool   `json:"held"`
	Deleted       bool   `json:"deleted"`
	SourcePresent bool   `json:"source_present"`
}

func remnawaveOwnerAllowed(ctx context.Context) bool {
	if _, ok := TenantPrincipal(ctx); ok {
		return false
	}
	if admin, ok := AdminPrincipal(ctx); ok {
		return admin.Account.Role == "owner"
	}
	return true // trusted root administrative caller; HTTP authentication is separate
}

func scanRemnawaveImport(row vpnClientRowScanner) (RemnawaveImport, error) {
	var v RemnawaveImport
	var raw []byte
	err := row.Scan(&v.ID, &v.TenantID, &v.State, &v.CreatedAt, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(raw, &v.Report)
	return v, err
}

const remnawaveImportColumns = `id::text,tenant_id::text,state,created_at,report`
const remnawaveCurrentColumns = `i.id::text,i.tenant_id::text,i.state,i.created_at,r.report`
const remnawaveCurrentFrom = `remnawave_imports i JOIN remnawave_import_heads h ON h.import_id=i.id JOIN remnawave_inventory_revisions r ON r.import_id=h.import_id AND r.inventory_sha256=h.inventory_sha256`

// Compare a new read-only export against the immutable staged inventory.
// This method never replaces the source snapshot or edits a held client.
func (p *Postgres) PreviewRemnawaveDelta(ctx context.Context, id, tenant string, raw []byte) (remnawave.DeltaReport, error) {
	var report remnawave.DeltaReport
	if !remnawaveOwnerAllowed(ctx) {
		return report, ErrNotFound
	}
	var before []byte
	err := p.Pool.QueryRow(ctx, `SELECT r.inventory FROM `+remnawaveCurrentFrom+` WHERE i.id=$1::uuid AND i.tenant_id=$2::uuid AND i.state='held'`, id, tenant).Scan(&before)
	if errors.Is(err, pgx.ErrNoRows) {
		return report, ErrNotFound
	}
	if err != nil {
		return report, err
	}
	return remnawave.Compare(before, raw)
}

// StageRemnawaveInventory is all-or-nothing and idempotent for exact inventory
// bytes. It never changes nodes, service membership, source accounts or DNS.
func (p *Postgres) StageRemnawaveInventory(ctx context.Context, tenant string, raw []byte, reviewedSHA string) (RemnawaveImport, bool, error) {
	var out RemnawaveImport
	if !remnawaveOwnerAllowed(ctx) {
		return out, false, ErrNotFound
	}
	inv, report, err := remnawave.Parse(raw)
	if err != nil {
		return out, false, err
	}
	if reviewedSHA != report.SHA256 {
		return out, false, ErrRemnawaveReview
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	// Source lock precedes tenant locks consistently across all import attempts.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1448103509,hashtext($1))`, inv.SourceOrigin); err != nil {
		return out, false, err
	}
	existing, err := scanRemnawaveImport(tx.QueryRow(ctx, `SELECT `+remnawaveCurrentColumns+` FROM `+remnawaveCurrentFrom+` WHERE i.source_origin=$1`, inv.SourceOrigin))
	if err == nil {
		if existing.TenantID != tenant || existing.Report.SHA256 != report.SHA256 {
			return out, false, ErrRemnawaveConflict
		}
		var held int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM remnawave_import_clients m LEFT JOIN vpn_clients c ON c.id=m.client_id WHERE m.import_id=$1::uuid AND m.source_present AND ((c.tenant_id=$2::uuid AND c.remnawave_hold AND c.status='disabled') OR (m.client_id IS NULL AND m.deleted_client_id IS NOT NULL AND m.deleted_at IS NOT NULL))`, existing.ID, tenant).Scan(&held); err != nil {
			return out, false, err
		}
		if held != report.Users {
			return out, false, ErrRemnawaveConflict
		}
		return existing, false, tx.Commit(ctx)
	}
	if !errors.Is(err, ErrNotFound) {
		return out, false, err
	}
	if err = lockTenantResource(ctx, tx, tenant); err != nil {
		return out, false, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, false, err
	}
	limits, err := scanTenantLimits(tx.QueryRow(ctx, tenantLimitsQuery, tenant))
	if err != nil {
		return out, false, err
	}
	if limits.MaxClients > 0 && len(inv.Users) > limits.MaxClients-limits.Clients {
		return out, false, ErrTenantQuota
	}
	summary, err := json.Marshal(report)
	if err != nil {
		return out, false, err
	}
	out, err = scanRemnawaveImport(tx.QueryRow(ctx, `INSERT INTO remnawave_imports(tenant_id,source_origin,inventory_sha256,inventory,report,user_count,captured_at) VALUES($1::uuid,$2,$3,$4,$5::jsonb,$6,$7) RETURNING `+remnawaveImportColumns, tenant, inv.SourceOrigin, report.SHA256, raw, summary, len(inv.Users), inv.CapturedAt))
	if err != nil {
		return out, false, err
	}
	// Normalize only the columns needed for held client records. Every original
	// source field, including independent passwords and policy, remains in raw.
	type heldUser struct {
		ID      int64     `json:"id"`
		Name    string    `json:"name"`
		VLESS   string    `json:"vless"`
		Status  string    `json:"status"`
		Expires time.Time `json:"expires"`
	}
	users := make([]heldUser, 0, len(inv.Users))
	for _, u := range inv.Users {
		users = append(users, heldUser{u.ID, u.Username, u.VLESSUUID, u.Status, u.ExpireAt})
	}
	normalized, err := json.Marshal(users)
	if err != nil {
		return out, false, err
	}
	_, err = tx.Exec(ctx, `WITH source AS (
 SELECT * FROM jsonb_to_recordset($3::jsonb) AS x(id bigint,name text,vless uuid,status text,expires timestamptz)
 ), created AS (
 INSERT INTO vpn_clients(tenant_id,name,vless_uuid,status,expires_at,remnawave_hold)
 SELECT $1::uuid,name,vless,'disabled',expires,true FROM source
 RETURNING id,vless_uuid
 ) INSERT INTO remnawave_import_clients(import_id,source_user_id,source_status,client_id)
 SELECT $2::uuid,s.id,s.status,c.id FROM source s JOIN created c ON c.vless_uuid=s.vless`, tenant, out.ID, normalized)
	if err != nil {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "23505" {
			return RemnawaveImport{}, false, ErrRemnawaveConflict
		}
		return RemnawaveImport{}, false, err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'remnawave.inventory_staged',$2,$3,jsonb_build_object('import_id',$4::text,'inventory_sha256',$5::text,'client_count',$6::integer,'state','held'))`, tenant, actorType, actorID, out.ID, report.SHA256, len(users))
	if err != nil {
		return RemnawaveImport{}, false, err
	}
	return out, true, tx.Commit(ctx)
}

func (p *Postgres) ListRemnawaveImports(ctx context.Context) ([]RemnawaveImport, error) {
	if !remnawaveOwnerAllowed(ctx) {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+remnawaveCurrentColumns+` FROM `+remnawaveCurrentFrom+` ORDER BY i.created_at DESC,i.id LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RemnawaveImport{}
	for rows.Next() {
		v, e := scanRemnawaveImport(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (p *Postgres) RemnawaveImportClients(ctx context.Context, id string, after int64, limit int) ([]RemnawaveImportClient, error) {
	if !remnawaveOwnerAllowed(ctx) || after < 0 || limit < 1 || limit > 250 {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT m.source_user_id,m.source_status,COALESCE(c.id,m.deleted_client_id)::text,COALESCE(c.name,m.deleted_client_name),COALESCE(c.remnawave_hold,false),(m.deleted_at IS NOT NULL),m.source_present FROM remnawave_import_clients m LEFT JOIN vpn_clients c ON c.id=m.client_id WHERE m.import_id=$1::uuid AND m.source_user_id>$2 ORDER BY m.source_user_id LIMIT $3`, id, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RemnawaveImportClient{}
	for rows.Next() {
		var v RemnawaveImportClient
		if err = rows.Scan(&v.SourceID, &v.SourceStatus, &v.ClientID, &v.Name, &v.Held, &v.Deleted, &v.SourcePresent); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
