package main

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
)

func (a *application) createVPNService(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if nodeID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"node id is required",
		)
		return
	}

	var input struct {
		Name          string  `json:"name"`
		Protocol      string  `json:"protocol"`
		Listen        string  `json:"listen"`
		Port          int     `json:"port"`
		Transport     string  `json:"transport"`
		Security      string  `json:"security"`
		PublicAddress *string `json:"public_address"`
		PublicPort    *int    `json:"public_port"`
	}

	if err := readJSON(
		r,
		&input,
	); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.Name =
		strings.TrimSpace(input.Name)

	input.Protocol =
		strings.ToLower(
			strings.TrimSpace(
				input.Protocol,
			),
		)

	input.Listen =
		strings.TrimSpace(input.Listen)

	input.Transport =
		strings.ToLower(
			strings.TrimSpace(
				input.Transport,
			),
		)

	input.Security =
		strings.ToLower(
			strings.TrimSpace(
				input.Security,
			),
		)

	if input.Listen == "" {
		input.Listen = "0.0.0.0"
	}

	if input.Name == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"name is required",
		)
		return
	}

	if input.Protocol == "" ||
		input.Transport == "" ||
		input.Security == "" {

		writeError(
			w,
			http.StatusBadRequest,
			"protocol, transport and security are required",
		)
		return
	}

	if input.Port < 1 ||
		input.Port > 65535 || input.Port == 10085 {

		writeError(
			w,
			http.StatusBadRequest,
			"port must be between 1 and 65535; 10085 is reserved for node management",
		)
		return
	}

	if input.PublicAddress != nil {
		value :=
			strings.TrimSpace(
				*input.PublicAddress,
			)

		if value == "" {
			writeError(
				w,
				http.StatusBadRequest,
				"public_address cannot be empty",
			)
			return
		}

		input.PublicAddress = &value
	}

	if (input.PublicAddress == nil) !=
		(input.PublicPort == nil) {

		writeError(
			w,
			http.StatusBadRequest,
			"public_address and public_port must be provided together",
		)
		return
	}

	if input.PublicPort != nil &&
		(*input.PublicPort < 1 ||
			*input.PublicPort > 65535) {

		writeError(
			w,
			http.StatusBadRequest,
			"public_port must be between 1 and 65535",
		)
		return
	}

	if input.Protocol == "pptp" {
		ip, err := netip.ParseAddr(input.Listen)
		if err != nil || !ip.Is4() || input.Port != 1723 || input.Transport != "tcp,gre" || input.Security != "mppe" || (input.PublicPort != nil && *input.PublicPort != 1723) {
			writeError(w, http.StatusBadRequest, "PPTP requires IPv4, TCP1723/GRE and MPPE")
			return
		}
	}
	if input.Protocol == "shadowsocks" && (input.Transport != "tcp,udp" || input.Security != "shadowsocks") {
		writeError(w, http.StatusBadRequest, "Shadowsocks requires native TCP/UDP and Shadowsocks security")
		return
	}
	if input.Protocol == "wireguard" && (input.Transport != "udp" || input.Security != "wireguard") {
		writeError(w, http.StatusBadRequest, "WireGuard requires native UDP and WireGuard security")
		return
	}
	if (input.Transport == "ws" || input.Transport == "grpc") && (input.Protocol != "vless" || input.Security != "tls") {
		writeError(w, http.StatusBadRequest, "WebSocket and gRPC require VLESS with TLS")
		return
	}
	service, err :=
		a.store.CreateVPNService(
			r.Context(),
			nodeID,
			input.Name,
			input.Protocol,
			input.Listen,
			input.Port,
			input.Transport,
			input.Security,
			input.PublicAddress,
			input.PublicPort,
		)

	switch {
	case errors.Is(err, store.ErrNodeRuntime):
		writeError(w, http.StatusConflict, "service protocol does not match the node runtime")
		return
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		service,
	)
}

func (a *application) listVPNServices(
	w http.ResponseWriter,
	r *http.Request,
) {
	nodeID := strings.TrimSpace(
		r.PathValue("id"),
	)

	services, err :=
		a.store.ListVPNServices(
			r.Context(),
			nodeID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"node not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"services": services,
		},
	)
}

func (a *application) getVPNService(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	service, err :=
		a.store.GetVPNService(
			r.Context(),
			serviceID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"vpn service not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		service,
	)
}

func (a *application) attachVPNClientToService(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	clientID :=
		strings.TrimSpace(
			r.PathValue("client_id"),
		)

	membership, err :=
		a.store.AttachVPNClientToService(
			r.Context(),
			serviceID,
			clientID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"compatible vpn service/client pair not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusCreated,
		membership,
	)
}

func (a *application) detachVPNClientFromService(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	clientID :=
		strings.TrimSpace(
			r.PathValue("client_id"),
		)

	if !accessPlanUUID.MatchString(serviceID) || !accessPlanUUID.MatchString(clientID) {
		writeError(w, http.StatusBadRequest, "valid service id and client id are required")
		return
	}

	_, err :=
		a.store.DetachVPNClientAndRebuild(
			r.Context(),
			serviceID,
			clientID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"vpn service/client membership not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	w.WriteHeader(
		http.StatusNoContent,
	)
}

func (a *application) updateVPNServicePublicEndpoint(
	w http.ResponseWriter,
	r *http.Request,
) {
	serviceID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if serviceID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"vpn service id is required",
		)
		return
	}

	var input struct {
		Name          *string `json:"name"`
		Listen        string  `json:"listen"`
		Port          int     `json:"port"`
		Transport     string  `json:"transport"`
		PublicAddress string  `json:"public_address"`
		PublicPort    int     `json:"public_port"`
	}

	if err := readJSON(r, &input); err != nil {
		writeError(
			w,
			http.StatusBadRequest,
			err.Error(),
		)
		return
	}

	input.PublicAddress =
		strings.TrimSpace(input.PublicAddress)
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if name == "" || !model.ValidSubscriptionName(name) {
			writeError(
				w,
				http.StatusBadRequest,
				"name must be one line of at most 200 characters",
			)
			return
		}
		input.Name = &name
	}
	input.Listen = strings.TrimSpace(input.Listen)
	input.Transport = strings.TrimSpace(input.Transport)
	listen, err := netip.ParseAddr(input.Listen)
	if err != nil || listen.Zone() != "" {
		writeError(
			w,
			http.StatusBadRequest,
			"listen must be an IPv4 or IPv6 address",
		)
		return
	}
	input.Listen = listen.String()
	if input.Port < 1 || input.Port > 65535 {
		writeError(
			w,
			http.StatusBadRequest,
			"port must be between 1 and 65535",
		)
		return
	}

	if input.PublicAddress == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"public_address is required",
		)
		return
	}
	if len(input.PublicAddress) > 253 || strings.ContainsAny(input.PublicAddress, " \t\r\n/@?#") {
		writeError(
			w,
			http.StatusBadRequest,
			"public_address must be a hostname or IP address without a URL path",
		)
		return
	}

	if input.PublicPort < 1 ||
		input.PublicPort > 65535 {
		writeError(
			w,
			http.StatusBadRequest,
			"public_port must be between 1 and 65535",
		)
		return
	}

	name := ""
	if input.Name != nil {
		name = *input.Name
	}

	service, state, err :=
		a.store.UpdateVPNServiceConfigurationAndRebuild(
			r.Context(),
			serviceID,
			name,
			input.Listen,
			input.Port,
			input.Transport,
			input.PublicAddress,
			input.PublicPort,
		)

	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(
			w,
			http.StatusNotFound,
			"vpn service not found",
		)
		return

	case errors.Is(err, store.ErrNodeRetired):
		writeError(w, http.StatusConflict, "retired node configuration cannot be edited")
		return

	case errors.Is(err, store.ErrVPNServiceFixedPort):
		writeError(w, http.StatusBadRequest, "PPTP listener port is fixed at 1723")
		return

	case errors.Is(err, store.ErrVPNServiceTransportInvalid):
		writeError(w, http.StatusBadRequest, "OpenVPN transport must be TCP or UDP")
		return

	case errors.Is(err, store.ErrVPNServiceTransportImmutable):
		writeError(w, http.StatusBadRequest, "transport for this protocol is managed by its protocol-specific configuration")
		return

	case errors.Is(err, store.ErrVPNServiceBindConflict):
		writeError(w, http.StatusConflict, "another protocol already uses this address and port")
		return

	case err != nil:
		writeError(
			w,
			http.StatusConflict,
			"configuration could not be applied to the node",
		)
		return
	}

	writeJSON(
		w,
		http.StatusAccepted,
		map[string]any{
			"service":    service,
			"generation": state.Generation,
			"status":     "accepted",
		},
	)
}

func (a *application) listVPNClientDirectServices(
	w http.ResponseWriter,
	r *http.Request,
) {
	clientID := strings.TrimSpace(
		r.PathValue("id"),
	)

	if !accessPlanUUID.MatchString(clientID) {
		writeError(
			w,
			http.StatusBadRequest,
			"valid client id is required",
		)
		return
	}

	serviceIDs, err :=
		a.store.ListVPNClientDirectServiceIDs(
			r.Context(),
			clientID,
		)

	switch {
	case errors.Is(
		err,
		store.ErrNotFound,
	):
		writeError(
			w,
			http.StatusNotFound,
			"vpn client not found",
		)
		return

	case err != nil:
		writeError(
			w,
			http.StatusInternalServerError,
			err.Error(),
		)
		return
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"service_ids": serviceIDs,
		},
	)
}
