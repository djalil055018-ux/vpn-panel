package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"vpn-platform/internal/store"
)

func (a *application) registerTLSServiceRoutes(mux *http.ServeMux) {
	for _, method := range []string{"GET", "PUT"} {
		mux.HandleFunc(method+" /api/v1/vpn-services/{id}/tls", a.requireAdmin(a.manageVPNServiceTLS))
	}
}
func (a *application) manageVPNServiceTLS(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !accessPlanUUID.MatchString(id) {
		writeError(w, 400, "invalid service id")
		return
	}
	if r.Method == "GET" {
		value, err := a.store.GetVPNServiceTLS(r.Context(), id)
		if err != nil {
			tlsServiceError(w, err)
			return
		}
		writeJSON(w, 200, value)
		return
	}
	var input struct {
		CertificateID string `json:"certificate_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil || !accessPlanUUID.MatchString(input.CertificateID) {
		writeError(w, 400, "certificate_id UUID is required")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		writeError(w, 400, "body must contain one JSON object")
		return
	}
	value, generation, err := a.store.ConfigureVPNServiceTLS(r.Context(), id, strings.ToLower(input.CertificateID))
	if err != nil {
		tlsServiceError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tls": value, "generation": generation})
}
func tlsServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "TLS configuration not found")
	case errors.Is(err, store.ErrVPNServiceTLSInvalid):
		writeError(w, 409, "a valid production certificate on the same node and tenant is required")
	default:
		writeError(w, 500, "TLS configuration could not be applied")
	}
}
