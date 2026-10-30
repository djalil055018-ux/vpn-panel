package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"vpn-platform/internal/botbridge"
	"vpn-platform/internal/store"
)

var reviewedXrayDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type xrayPreparationRequest struct {
	TenantID     string            `json:"tenant_id"`
	NodeID       string            `json:"node_id"`
	SourceNodeID string            `json:"source_node_id"`
	TLS          []json.RawMessage `json:"tls_assignments"`
}

func decodeXrayPreparation(raw []byte) (xrayPreparationRequest, []store.XrayProfileTLSAssignment, error) {
	var req xrayPreparationRequest
	if botbridge.DecodeRequest(raw, &req, "tenant_id", "node_id", "source_node_id", "tls_assignments") != nil ||
		!accessPlanUUID.MatchString(req.TenantID) || !accessPlanUUID.MatchString(req.NodeID) ||
		!accessPlanUUID.MatchString(req.SourceNodeID) || req.TLS == nil || len(req.TLS) > 128 {
		return req, nil, botbridge.ErrRequest
	}
	assignments := []store.XrayProfileTLSAssignment{}
	for _, raw := range req.TLS {
		var a store.XrayProfileTLSAssignment
		if botbridge.DecodeRequest(raw, &a, "source_inbound_id", "certificate_id") != nil ||
			!accessPlanUUID.MatchString(a.SourceInboundID) || !accessPlanUUID.MatchString(a.CertificateID) {
			return req, nil, botbridge.ErrRequest
		}
		assignments = append(assignments, a)
	}
	return req, assignments, nil
}

func (a *application) prepareRemnawaveXrayNode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !adminOwnerRequired(w, r) {
		return
	}
	digest := r.Header.Get("X-Reviewed-Inventory-SHA256")
	if !accessPlanUUID.MatchString(r.PathValue("id")) || !reviewedXrayDigest.MatchString(digest) || r.Header.Get("X-Remnawave-Mode") != "prepare-held-xray" {
		writeError(w, 400, "explicit held Xray preparation and reviewed inventory required")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if err != nil {
		writeError(w, 400, "invalid Xray preparation request")
		return
	}
	req, tls, err := decodeXrayPreparation(raw)
	if err != nil {
		writeError(w, 400, "invalid Xray preparation request")
		return
	}
	out, err := a.store.PrepareXrayProfile(r.Context(), req.TenantID, r.PathValue("id"), req.NodeID, req.SourceNodeID, digest, tls)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrXrayProfileHeld), errors.Is(err, store.ErrXrayProfileIdentity), errors.Is(err, store.ErrVPNServiceTLSInvalid):
			writeError(w, 409, err.Error())
		default:
			remnawaveError(w, err)
		}
		return
	}
	writeJSON(w, 200, out)
}
