package main

import (
	"errors"
	"io"
	"net/http"
	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/store"
)

func decodeImportedTLSPreparation(raw []byte) (store.ImportedTLSRequest, error) {
	var req store.ImportedTLSRequest
	if botbridge.DecodeRequestLimit(raw, &req, 96<<10, "tenant_id", "node_id", "source_node_id", "domain", "fullchain_pem", "adoption_sha256") != nil ||
		!accessPlanUUID.MatchString(req.TenantID) || !accessPlanUUID.MatchString(req.NodeID) || !accessPlanUUID.MatchString(req.SourceNodeID) ||
		!reviewedXrayDigest.MatchString(req.AdoptionSHA256) || len(req.Domain) == 0 || len(req.Domain) > 253 || len(req.FullchainPEM) == 0 || len(req.FullchainPEM) > 65536 {
		return req, botbridge.ErrRequest
	}
	return req, nil
}

func (a *application) prepareRemnawaveTLS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !adminOwnerRequired(w, r) {
		return
	}
	digest := r.Header.Get("X-Reviewed-Inventory-SHA256")
	if !accessPlanUUID.MatchString(r.PathValue("id")) || !reviewedXrayDigest.MatchString(digest) || r.Header.Get("X-Remnawave-Mode") != "prepare-held-tls" {
		writeError(w, 400, "explicit held TLS preparation and reviewed inventory required")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 96<<10))
	if err != nil {
		writeError(w, 400, "invalid TLS preparation request")
		return
	}
	req, err := decodeImportedTLSPreparation(raw)
	if err != nil {
		writeError(w, 400, "invalid TLS preparation request")
		return
	}
	out, err := a.store.PrepareImportedTLS(r.Context(), r.PathValue("id"), digest, req)
	if err != nil {
		if errors.Is(err, store.ErrImportedTLS) {
			writeError(w, 409, "certificate or node differs from reviewed TLS material")
		} else {
			remnawaveError(w, err)
		}
		return
	}
	writeJSON(w, 200, map[string]any{"preparation": out, "physical_proof": "owner_attestation", "cutover_ready": false})
}
