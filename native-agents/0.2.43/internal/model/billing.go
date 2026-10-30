package model

import "time"

type BillingOffer struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	PlanID       string    `json:"plan_id"`
	Name         string    `json:"name"`
	AmountMinor  int64     `json:"amount_minor"`
	Currency     string    `json:"currency"`
	DurationDays int       `json:"duration_days"`
	Enabled      bool      `json:"enabled"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type BillingInvoice struct {
	ID                   string     `json:"id"`
	TenantID             string     `json:"tenant_id"`
	OfferID              string     `json:"offer_id"`
	ClientID             string     `json:"client_id"`
	ClientDeleted        bool       `json:"client_deleted,omitempty"`
	PlanID               string     `json:"plan_id"`
	OfferName            string     `json:"offer_name"`
	AmountMinor          int64      `json:"amount_minor"`
	Currency             string     `json:"currency"`
	DurationDays         int        `json:"duration_days"`
	Status               string     `json:"status"`
	PaymentReference     *string    `json:"payment_reference"`
	PaymentSource        *string    `json:"payment_source"`
	PaidAt               *time.Time `json:"paid_at"`
	EntitlementExpiresAt *time.Time `json:"entitlement_expires_at"`
	CreatedAt            time.Time  `json:"created_at"`
}
type BillingSettlement struct {
	Invoice  BillingInvoice      `json:"invoice"`
	Changed  bool                `json:"changed"`
	Rebuilds []NodeRebuildResult `json:"rebuilds"`
}
