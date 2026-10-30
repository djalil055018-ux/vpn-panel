package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"vpn-platform/internal/store"
)

func (a *application) registerCertificateManagementRoutes(mux *http.ServeMux) {
	for _, route := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"PATCH /api/v1/certificates/{id}", a.setCertificateAutoRenew},
		{"POST /api/v1/certificates/{id}/archive", a.archiveCertificate},
		{"DELETE /api/v1/certificates/{id}", a.deleteCertificate},
		{"GET /api/v1/certificates/{id}/jobs", a.listCertificateJobs},
	} {
		handler := route.handler
		mux.HandleFunc(route.path, a.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
			if !accessPlanUUID.MatchString(r.PathValue("id")) {
				writeError(w, 400, "invalid certificate id")
				return
			}
			handler(w, r)
		}))
	}
}

func (a *application) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	if principal, ok := store.AdminPrincipal(r.Context()); ok && principal.Account.Role != "owner" {
		writeError(w, http.StatusForbidden, "owner role required")
		return
	}
	var input struct {
		ConfirmDomain string `json:"confirm_domain"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || strings.TrimSpace(input.ConfirmDomain) == "" || len(input.ConfirmDomain) > 253 {
		writeError(w, http.StatusBadRequest, "exact domain confirmation required")
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		writeError(w, http.StatusBadRequest, "body must contain one JSON object")
		return
	}
	job, err := a.store.QueueCertificateDeletion(r.Context(), r.PathValue("id"), strings.TrimSpace(input.ConfirmDomain))
	if err != nil {
		certificateManagementError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": job, "queued": true, "files_removed": false})
}
func certificateManagementError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "certificate not found")
	case errors.Is(err, store.ErrCertificateJobExists):
		writeError(w, 409, "wait for the active certificate operation to finish")
	case errors.Is(err, store.ErrCertificateInUse):
		writeError(w, 409, "certificate is assigned to a VPN service")
	case errors.Is(err, store.ErrCertificateJobInvalidState):
		writeError(w, 409, "certificate is archived, in use, on an unsupported or retiring node, or confirmation does not match")
	default:
		writeError(w, 500, "certificate operation failed")
	}
}
func (a *application) setCertificateAutoRenew(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AutoRenew *bool `json:"auto_renew"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.AutoRenew == nil {
		writeError(w, 400, "auto_renew boolean is required")
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		writeError(w, 400, "body must contain one JSON object")
		return
	}
	if err := a.store.SetCertificateAutoRenew(r.Context(), r.PathValue("id"), *input.AutoRenew); err != nil {
		certificateManagementError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *application) archiveCertificate(w http.ResponseWriter, r *http.Request) {
	if err := a.store.ArchiveNodeCertificate(r.Context(), r.PathValue("id")); err != nil {
		certificateManagementError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"archived": true, "ca_revocation_performed": false, "installed_files_preserved": true})
}
func (a *application) listCertificateJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := a.store.ListCertificateJobs(r.Context(), r.PathValue("id"))
	if err != nil {
		certificateManagementError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"jobs": jobs})
}
