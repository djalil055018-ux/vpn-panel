package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

var billingKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{8,128}$`)

func billingCurrency(value string) bool {
	return value == "RUB" || value == "USD" || value == "EUR" || value == "PLN" || value == "SEK"
}
func writeBillingError(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "billing resource not found")
	case errors.Is(err, store.ErrBillingConflict):
		writeError(w, 409, "billing state or idempotency conflict")
	case errors.Is(err, store.ErrBillingAmountMismatch):
		writeError(w, 400, "payment amount or currency does not match invoice")
	case errors.As(err, &pg) && (pg.Code == "23503" || pg.Code == "23505" || pg.Code == "40001" || pg.Code == "40P01"):
		writeError(w, 409, "billing resource changed or is still in use")
	default:
		writeError(w, 500, "billing operation failed; retry with the same idempotency key")
	}
}
func (a *application) registerBillingRoutes(mux *http.ServeMux) {
	for _, route := range []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /api/v1/tenants/{id}/billing/offers", a.listBillingOffers}, {"POST /api/v1/tenants/{id}/billing/offers", a.createBillingOffer},
		{"PUT /api/v1/billing/offers/{id}", a.updateBillingOffer},
		{"GET /api/v1/tenants/{id}/billing/invoices", a.listBillingInvoices}, {"POST /api/v1/tenants/{id}/billing/invoices", a.createBillingInvoice},
		{"GET /api/v1/billing/invoices/{id}", a.getBillingInvoice}, {"POST /api/v1/billing/invoices/{id}/settle", a.settleBillingInvoice}, {"POST /api/v1/billing/invoices/{id}/void", a.voidBillingInvoice},
	} {
		h := route.handler
		mux.HandleFunc(route.pattern, a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if !accessPlanUUID.MatchString(r.PathValue("id")) {
				writeError(w, 400, "invalid id")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			h(w, r.WithContext(ctx))
		}))
	}
	mux.HandleFunc("GET /api/v1/billing/integration-status", a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"payment_webhook_enabled": len(os.Getenv("BILLING_WEBHOOK_SECRET")) >= 32, "provider": "generic_hmac", "automatic_payment_capture": false})
	}))
	mux.HandleFunc("POST /api/v1/billing/payment-events", a.billingPaymentEvent)
	mux.HandleFunc("GET /api/v1/tenant/offers", a.requireTenantAPI("tenant", false, a.listBillingOffers))
	mux.HandleFunc("GET /api/v1/tenant/invoices", a.requireTenantAPI("tenant", false, a.listBillingInvoices))
	mux.HandleFunc("POST /api/v1/tenant/invoices", a.requireTenantAPI("tenant", true, a.createBillingInvoice))
	mux.HandleFunc("GET /api/v1/tenant/invoices/{id}", a.requireTenantAPI("invoice", false, a.getBillingInvoice))
}
func readBillingOffer(w http.ResponseWriter, r *http.Request, create bool) (model.BillingOffer, error) {
	var input struct {
		PlanID       string `json:"plan_id"`
		Name         string `json:"name"`
		AmountMinor  int64  `json:"amount_minor"`
		Currency     string `json:"currency"`
		DurationDays int    `json:"duration_days"`
		Enabled      *bool  `json:"enabled"`
	}
	err := tenantReadJSON(w, r, &input)
	o := model.BillingOffer{PlanID: input.PlanID, Name: strings.TrimSpace(input.Name), AmountMinor: input.AmountMinor, Currency: input.Currency, DurationDays: input.DurationDays, Enabled: true}
	if input.Enabled != nil {
		o.Enabled = *input.Enabled
	}
	if err != nil || o.Name == "" || len(o.Name) > 200 || o.AmountMinor < 1 || o.AmountMinor > 1000000000000 || !billingCurrency(o.Currency) || o.DurationDays < 1 || o.DurationDays > 3650 || create && !accessPlanUUID.MatchString(o.PlanID) || !create && o.PlanID != "" {
		return o, errors.New("invalid offer")
	}
	return o, nil
}
func (a *application) createBillingOffer(w http.ResponseWriter, r *http.Request) {
	o, err := readBillingOffer(w, r, true)
	if err != nil {
		writeError(w, 400, "name, plan, positive minor-unit amount, supported currency and duration required")
		return
	}
	out, err := a.store.CreateBillingOffer(r.Context(), r.PathValue("id"), o)
	if err != nil {
		writeBillingError(w, err)
		return
	}
	writeJSON(w, 201, out)
}
func (a *application) updateBillingOffer(w http.ResponseWriter, r *http.Request) {
	o, err := readBillingOffer(w, r, false)
	if err != nil {
		writeError(w, 400, "invalid offer update; plan cannot be changed")
		return
	}
	out, err := a.store.UpdateBillingOffer(r.Context(), r.PathValue("id"), o)
	if err != nil {
		writeBillingError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (a *application) listBillingOffers(w http.ResponseWriter, r *http.Request) {
	_, tenant := store.TenantPrincipal(r.Context())
	out, err := a.store.ListBillingOffers(r.Context(), r.PathValue("id"), tenant)
	if err != nil {
		writeBillingError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"offers": out})
}
func (a *application) createBillingInvoice(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OfferID  string `json:"offer_id"`
		ClientID string `json:"client_id"`
	}
	key := r.Header.Get("Idempotency-Key")
	if tenantReadJSON(w, r, &input) != nil || !accessPlanUUID.MatchString(input.OfferID) || !accessPlanUUID.MatchString(input.ClientID) || !billingKeyPattern.MatchString(key) {
		writeError(w, 400, "offer_id, client_id and Idempotency-Key required")
		return
	}
	out, created, err := a.store.CreateBillingInvoice(r.Context(), r.PathValue("id"), input.OfferID, input.ClientID, key)
	if err != nil {
		writeBillingError(w, err)
		return
	}
	status := 200
	if created {
		status = 201
	}
	writeJSON(w, status, out)
}
func (a *application) listBillingInvoices(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.ListBillingInvoices(r.Context(), r.PathValue("id"))
	if err != nil {
		writeBillingError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"invoices": out})
}
func (a *application) getBillingInvoice(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.GetBillingInvoice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeBillingError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (a *application) voidBillingInvoice(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.VoidBillingInvoice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeBillingError(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (a *application) settleBillingInvoice(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Reference string `json:"payment_reference"`
		Received  bool   `json:"payment_received"`
	}
	if tenantReadJSON(w, r, &input) != nil || !input.Received || strings.TrimSpace(input.Reference) == "" || len(input.Reference) > 200 {
		writeError(w, 400, "payment_received confirmation and payment_reference required")
		return
	}
	invoice, err := a.store.GetBillingInvoice(r.Context(), r.PathValue("id"))
	if err != nil {
		writeBillingError(w, err)
		return
	}
	result, err := a.store.SettleBillingInvoice(r.Context(), store.BillingPayment{InvoiceID: invoice.ID, Reference: strings.TrimSpace(input.Reference), Source: "manual", AmountMinor: invoice.AmountMinor, Currency: invoice.Currency})
	if err != nil {
		writeBillingError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func validBillingSignature(secret, timestamp, signature string, body []byte, now time.Time) bool {
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || seconds < now.Unix()-300 || seconds > now.Unix()+30 {
		return false
	}
	supplied, err := hex.DecodeString(signature)
	if err != nil || len(supplied) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hmac.Equal(supplied, mac.Sum(nil))
}
func (a *application) billingPaymentEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	secret := os.Getenv("BILLING_WEBHOOK_SECRET")
	if len(secret) < 32 {
		writeError(w, 503, "payment webhook is not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, 400, "invalid event body")
		return
	}
	if !validBillingSignature(secret, r.Header.Get("X-VPN-Timestamp"), r.Header.Get("X-VPN-Signature"), body, time.Now().UTC()) {
		writeError(w, 401, "invalid payment signature")
		return
	}
	var input struct {
		EventID     string `json:"event_id"`
		InvoiceID   string `json:"invoice_id"`
		Reference   string `json:"payment_reference"`
		AmountMinor int64  `json:"amount_minor"`
		Currency    string `json:"currency"`
		Status      string `json:"status"`
	}
	d := json.NewDecoder(strings.NewReader(string(body)))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&input) != nil || d.Decode(&extra) != io.EOF || !billingKeyPattern.MatchString(input.EventID) || !accessPlanUUID.MatchString(input.InvoiceID) || strings.TrimSpace(input.Reference) == "" || len(input.Reference) > 200 || input.Status != "paid" || input.AmountMinor < 1 || !billingCurrency(input.Currency) {
		writeError(w, 400, "invalid payment event")
		return
	}
	canonical, _ := json.Marshal(input)
	digest := sha256.Sum256(canonical)
	result, err := a.store.SettleBillingInvoice(r.Context(), store.BillingPayment{InvoiceID: input.InvoiceID, Reference: input.Reference, Source: "webhook", AmountMinor: input.AmountMinor, Currency: input.Currency, EventID: input.EventID, PayloadHash: hex.EncodeToString(digest[:])})
	if err != nil {
		writeBillingError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
