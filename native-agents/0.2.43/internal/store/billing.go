package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"vpn-platform/internal/model"
)

var ErrBillingConflict = errors.New("billing operation conflicts with existing state")
var ErrBillingAmountMismatch = errors.New("payment amount or currency mismatch")

const billingOfferColumns = `id::text,tenant_id::text,plan_id::text,name,amount_minor,currency,duration_days,enabled,created_at,updated_at`
const billingInvoiceColumns = `id::text,tenant_id::text,offer_id::text,client_id::text,plan_id::text,offer_name,amount_minor,currency,duration_days,status,payment_reference,payment_source,paid_at,entitlement_expires_at,created_at,(deleted_client_id IS NOT NULL)`

func scanBillingOffer(row pgx.Row) (model.BillingOffer, error) {
	var o model.BillingOffer
	err := row.Scan(&o.ID, &o.TenantID, &o.PlanID, &o.Name, &o.AmountMinor, &o.Currency, &o.DurationDays, &o.Enabled, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return o, err
}
func scanBillingInvoice(row pgx.Row) (model.BillingInvoice, error) {
	var i model.BillingInvoice
	err := row.Scan(&i.ID, &i.TenantID, &i.OfferID, &i.ClientID, &i.PlanID, &i.OfferName, &i.AmountMinor, &i.Currency, &i.DurationDays, &i.Status, &i.PaymentReference, &i.PaymentSource, &i.PaidAt, &i.EntitlementExpiresAt, &i.CreatedAt, &i.ClientDeleted)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return i, err
}
func (p *Postgres) CreateBillingOffer(ctx context.Context, tenant string, o model.BillingOffer) (model.BillingOffer, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return model.BillingOffer{}, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.BillingOffer{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	out, err := scanBillingOffer(tx.QueryRow(ctx, `INSERT INTO billing_offers(tenant_id,plan_id,name,amount_minor,currency,duration_days,enabled) SELECT tenant_id,id,$3,$4,$5,$6,$7 FROM vpn_access_plans WHERE tenant_id=$1::uuid AND id=$2::uuid RETURNING `+billingOfferColumns, tenant, o.PlanID, o.Name, o.AmountMinor, o.Currency, o.DurationDays, o.Enabled))
	if err != nil {
		return out, err
	}
	if err = billingOfferAudit(ctx, tx, out, "created"); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func (p *Postgres) UpdateBillingOffer(ctx context.Context, id string, o model.BillingOffer) (model.BillingOffer, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return model.BillingOffer{}, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.BillingOffer{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	out, err := scanBillingOffer(tx.QueryRow(ctx, `UPDATE billing_offers SET name=$2,amount_minor=$3,currency=$4,duration_days=$5,enabled=$6,updated_at=now() WHERE id=$1::uuid RETURNING `+billingOfferColumns, id, o.Name, o.AmountMinor, o.Currency, o.DurationDays, o.Enabled))
	if err != nil {
		return out, err
	}
	if err = billingOfferAudit(ctx, tx, out, "updated"); err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}
func billingOfferAudit(ctx context.Context, tx pgx.Tx, o model.BillingOffer, event string) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,$2,'admin','control-plane',jsonb_build_object('offer_id',$3::text,'amount_minor',$4::bigint,'currency',$5::text,'duration_days',$6::integer,'enabled',$7::boolean))`, o.TenantID, "billing.offer_"+event, o.ID, o.AmountMinor, o.Currency, o.DurationDays, o.Enabled)
	return err
}
func (p *Postgres) ListBillingOffers(ctx context.Context, tenant string, enabledOnly bool) ([]model.BillingOffer, error) {
	if !tenantScopeAllowed(ctx, tenant) {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+billingOfferColumns+` FROM billing_offers WHERE tenant_id=$1::uuid AND (NOT $2::boolean OR enabled) ORDER BY created_at DESC,id`, tenant, enabledOnly)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BillingOffer{}
	for rows.Next() {
		o, err := scanBillingOffer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (p *Postgres) ListBillingInvoices(ctx context.Context, tenant string) ([]model.BillingInvoice, error) {
	if !tenantScopeAllowed(ctx, tenant) {
		return nil, ErrNotFound
	}
	rows, err := p.Pool.Query(ctx, `SELECT `+billingInvoiceColumns+` FROM billing_invoices WHERE tenant_id=$1::uuid ORDER BY created_at DESC,id LIMIT 200`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BillingInvoice{}
	for rows.Next() {
		i, err := scanBillingInvoice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
func (p *Postgres) GetBillingInvoice(ctx context.Context, id string) (model.BillingInvoice, error) {
	i, err := scanBillingInvoice(p.Pool.QueryRow(ctx, `SELECT `+billingInvoiceColumns+` FROM billing_invoices WHERE id=$1::uuid`, id))
	if err == nil && !tenantScopeAllowed(ctx, i.TenantID) {
		return model.BillingInvoice{}, ErrNotFound
	}
	return i, err
}
func (p *Postgres) CreateBillingInvoice(ctx context.Context, tenant, offer, client, key string) (model.BillingInvoice, bool, error) {
	var out model.BillingInvoice
	if !tenantScopeAllowed(ctx, tenant) {
		return out, false, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, false, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, false, err
	}
	prior, err := scanBillingInvoice(tx.QueryRow(ctx, `SELECT `+billingInvoiceColumns+` FROM billing_invoices WHERE tenant_id=$1::uuid AND idempotency_key=$2`, tenant, key))
	if err == nil {
		if prior.OfferID != offer || prior.ClientID != client {
			return out, false, ErrBillingConflict
		}
		return prior, false, tx.Commit(ctx)
	}
	if !errors.Is(err, ErrNotFound) {
		return out, false, err
	}
	out, err = scanBillingInvoice(tx.QueryRow(ctx, `INSERT INTO billing_invoices(tenant_id,offer_id,client_id,plan_id,offer_name,amount_minor,currency,duration_days,idempotency_key)
 SELECT o.tenant_id,o.id,c.id,o.plan_id,o.name,o.amount_minor,o.currency,o.duration_days,$4 FROM billing_offers o JOIN vpn_clients c ON c.tenant_id=o.tenant_id AND c.id=$3::uuid JOIN vpn_access_plans ap ON ap.id=o.plan_id AND ap.tenant_id=o.tenant_id WHERE o.tenant_id=$1::uuid AND o.id=$2::uuid AND o.enabled AND ap.enabled RETURNING `+billingInvoiceColumns, tenant, offer, client, key))
	if err != nil {
		return out, false, err
	}
	actorType, actorID := accessActor(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'billing.invoice_created',$2,$3,jsonb_build_object('invoice_id',$4::text))`, tenant, actorType, actorID, out.ID)
	if err != nil {
		return out, false, err
	}
	return out, true, tx.Commit(ctx)
}
func (p *Postgres) VoidBillingInvoice(ctx context.Context, id string) (model.BillingInvoice, error) {
	if _, scoped := TenantPrincipal(ctx); scoped {
		return model.BillingInvoice{}, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return model.BillingInvoice{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	invoice, err := scanBillingInvoice(tx.QueryRow(ctx, `SELECT `+billingInvoiceColumns+` FROM billing_invoices WHERE id=$1::uuid FOR UPDATE`, id))
	if err != nil {
		return invoice, err
	}
	if invoice.Status == "paid" {
		return invoice, ErrBillingConflict
	}
	if invoice.Status == "void" {
		return invoice, tx.Commit(ctx)
	}
	invoice, err = scanBillingInvoice(tx.QueryRow(ctx, `UPDATE billing_invoices SET status='void' WHERE id=$1::uuid RETURNING `+billingInvoiceColumns, id))
	if err != nil {
		return invoice, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'billing.invoice_voided','admin','control-plane',jsonb_build_object('invoice_id',$2::text))`, invoice.TenantID, id)
	if err != nil {
		return invoice, err
	}
	return invoice, tx.Commit(ctx)
}

type BillingPayment struct {
	InvoiceID, Reference, Source, EventID, PayloadHash, Currency string
	AmountMinor                                                  int64
}

func (p *Postgres) SettleBillingInvoice(ctx context.Context, payment BillingPayment) (model.BillingSettlement, error) {
	out := model.BillingSettlement{Rebuilds: []model.NodeRebuildResult{}}
	if _, scoped := TenantPrincipal(ctx); scoped {
		return out, ErrNotFound
	}
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var tenant string
	err = tx.QueryRow(ctx, `SELECT tenant_id::text FROM billing_invoices WHERE id=$1::uuid`, payment.InvoiceID).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if err = lockTenantAccess(ctx, tx, tenant); err != nil {
		return out, err
	}
	invoice, err := scanBillingInvoice(tx.QueryRow(ctx, `SELECT `+billingInvoiceColumns+` FROM billing_invoices WHERE id=$1::uuid FOR UPDATE`, payment.InvoiceID))
	if err != nil {
		return out, err
	}
	out.Invoice = invoice
	if payment.AmountMinor != invoice.AmountMinor || payment.Currency != invoice.Currency {
		return out, ErrBillingAmountMismatch
	}
	if payment.EventID != "" {
		tag, err := tx.Exec(ctx, `INSERT INTO billing_payment_events(event_id,invoice_id,payload_hash) VALUES($1,$2::uuid,$3) ON CONFLICT DO NOTHING`, payment.EventID, invoice.ID, payment.PayloadHash)
		if err != nil {
			return out, err
		}
		if tag.RowsAffected() == 0 {
			var id, hash string
			if err = tx.QueryRow(ctx, `SELECT invoice_id::text,payload_hash FROM billing_payment_events WHERE event_id=$1`, payment.EventID).Scan(&id, &hash); err != nil {
				return out, err
			}
			if id != invoice.ID || hash != payment.PayloadHash {
				return out, ErrBillingConflict
			}
		}
	}
	if invoice.Status == "paid" {
		if invoice.PaymentReference == nil || *invoice.PaymentReference != payment.Reference || invoice.PaymentSource == nil || *invoice.PaymentSource != payment.Source {
			return out, ErrBillingConflict
		}
		return out, tx.Commit(ctx)
	}
	if invoice.Status != "pending" {
		return out, ErrBillingConflict
	}
	rows, err := tx.Query(ctx, `SELECT service_id::text FROM vpn_effective_client_services WHERE client_id=$1::uuid AND tenant_id=$2::uuid`, invoice.ClientID, tenant)
	if err != nil {
		return out, err
	}
	before := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return out, err
		}
		before = append(before, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO billing_entitlements(tenant_id,client_id,plan_id,expires_at) VALUES($1::uuid,$2::uuid,$3::uuid,now()+($4::integer * interval '24 hours')) ON CONFLICT(client_id,plan_id) DO UPDATE SET expires_at=GREATEST(billing_entitlements.expires_at,now())+($4::integer * interval '24 hours'),updated_at=now()`, tenant, invoice.ClientID, invoice.PlanID, invoice.DurationDays)
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT DISTINCT s.node_id::text FROM vpn_effective_client_services e JOIN vpn_services s ON s.id=e.service_id AND s.tenant_id=e.tenant_id JOIN vpn_clients c ON c.id=e.client_id AND c.tenant_id=e.tenant_id WHERE e.client_id=$1::uuid AND e.tenant_id=$2::uuid AND NOT(s.id=ANY($3::uuid[])) AND s.enabled AND c.status='active' AND (c.expires_at IS NULL OR c.expires_at>now()) UNION SELECT e.entry_node_id::text FROM vpn_effective_client_cascades e WHERE e.client_id=$1::uuid AND e.tenant_id=$2::uuid ORDER BY 1`, invoice.ClientID, tenant, before)
	if err != nil {
		return out, err
	}
	nodes := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return out, err
		}
		nodes = append(nodes, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	for _, node := range nodes {
		state, release, err := buildNodeDesiredStateTx(ctx, tx, node)
		if err != nil {
			return out, err
		}
		if err = saveDesiredStateTx(ctx, tx, node, state, release); err != nil {
			return out, err
		}
		out.Rebuilds = append(out.Rebuilds, model.NodeRebuildResult{NodeID: node, Generation: state.Generation})
	}
	out.Invoice, err = scanBillingInvoice(tx.QueryRow(ctx, `UPDATE billing_invoices SET status='paid',payment_reference=$2,payment_source=$3,paid_at=now(),entitlement_expires_at=(SELECT expires_at FROM billing_entitlements WHERE client_id=$4::uuid AND plan_id=$5::uuid) WHERE id=$1::uuid RETURNING `+billingInvoiceColumns, invoice.ID, payment.Reference, payment.Source, invoice.ClientID, invoice.PlanID))
	if err != nil {
		return out, err
	}
	actorType, actorID := "admin", "control-plane"
	if payment.Source == "webhook" {
		actorType, actorID = "integration", "billing-webhook"
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,event_type,actor_type,actor_id,payload) VALUES($1::uuid,'billing.invoice_paid',$2,$3,jsonb_build_object('invoice_id',$4::text,'rebuild_count',$5::integer))`, tenant, actorType, actorID, invoice.ID, len(out.Rebuilds))
	if err != nil {
		return out, err
	}
	out.Changed = true
	return out, tx.Commit(ctx)
}
