package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"vpn-platform/internal/compiler"
	"vpn-platform/internal/model"
	"vpn-platform/internal/store"
	"vpn-platform/internal/subscriptioncompat"
)

func buildVPNConnectionURI(
	connection model.VPNClientConnection,
) (
	string,
	error,
) {
	if connection.ImportedProfile != nil {
		var h subscriptioncompat.Host
		if err := json.Unmarshal(connection.ImportedProfile, &h); err != nil {
			return "", err
		}
		return subscriptioncompat.ShareURI(h, connection.UUID)
	}
	if connection.Protocol == "wireguard" || connection.Protocol == "openvpn" || connection.Protocol == "pptp" {
		if connection.Config == "" {
			return "", errors.New("VPN profile missing")
		}
		return "", nil
	}
	if connection.Protocol == "shadowsocks" {
		parts := strings.Split(connection.Password, ":")
		if connection.Transport != "tcp,udp" || connection.Security != "shadowsocks" || len(parts) != 2 || !model.ValidShadowsocksKey(parts[0]) || !model.ValidShadowsocksKey(parts[1]) || parts[0] == parts[1] || strings.TrimSpace(connection.Address) == "" || connection.Port < 1 || connection.Port > 65535 {
			return "", errors.New("invalid Shadowsocks connection")
		}
		u := url.URL{Scheme: "ss", User: url.UserPassword(model.ShadowsocksMethod, connection.Password), Host: net.JoinHostPort(connection.Address, strconv.Itoa(connection.Port)), Fragment: vpnConnectionDisplayName(connection)}
		return u.String(), nil
	}
	if connection.Protocol == "hysteria2" {
		connection.ServiceName = vpnConnectionDisplayName(connection)
		return compiler.HysteriaURI(connection)
	}
	if connection.Security == "tls" {
		if strings.TrimSpace(connection.Address) == "" || connection.Port < 1 || connection.Port > 65535 || connection.ServerName == "" || !accessPlanUUID.MatchString(connection.UUID) || (connection.Protocol != "vless" && connection.Protocol != "trojan") || (connection.Transport != "tcp" && !(model.VLESSTLSTransport(connection.Transport) && connection.Protocol == "vless")) {
			return "", errors.New("invalid TLS connection")
		}
		q := url.Values{"encryption": {"none"}, "security": {"tls"}, "type": {"tcp"}, "sni": {connection.ServerName}, "fp": {"chrome"}}
		if connection.Protocol == "trojan" {
			q.Del("encryption")
		}
		if connection.Transport == "ws" {
			path, ok := model.XHTTPPath(connection.ServiceID)
			if !ok {
				return "", errors.New("invalid WebSocket service ID")
			}
			q.Set("type", "ws")
			q.Set("path", path)
			q.Set("host", connection.ServerName)
		}
		if connection.Transport == "grpc" {
			name, ok := model.GRPCServiceName(connection.ServiceID)
			if !ok {
				return "", errors.New("invalid gRPC service ID")
			}
			q.Set("type", "grpc")
			q.Set("serviceName", name)
			q.Set("mode", "gun")
		}
		if connection.Transport == "xhttp" {
			path, ok := model.XHTTPPath(connection.ServiceID)
			if !ok {
				return "", errors.New("invalid XHTTP service ID")
			}
			q.Set("type", "xhttp")
			q.Set("path", path)
			q.Set("mode", "auto")
		}
		u := url.URL{Scheme: connection.Protocol, User: url.User(connection.UUID), Host: net.JoinHostPort(connection.Address, strconv.Itoa(connection.Port)), RawQuery: q.Encode(), Fragment: vpnConnectionDisplayName(connection)}
		return u.String(), nil
	}
	host :=
		strings.TrimSpace(
			connection.Address,
		)

	if host == "" ||
		connection.Port < 1 ||
		connection.Port > 65535 {

		return "",
			errors.New(
				"invalid public endpoint",
			)
	}

	query :=
		url.Values{}

	query.Set(
		"encryption",
		"none",
	)

	query.Set(
		"security",
		"reality",
	)

	query.Set(
		"type",
		"tcp",
	)

	query.Set(
		"sni",
		connection.ServerName,
	)

	query.Set(
		"fp",
		connection.Fingerprint,
	)

	query.Set(
		"pbk",
		connection.Password,
	)

	query.Set(
		"sid",
		connection.ShortID,
	)

	name := vpnConnectionDisplayName(connection)

	value :=
		url.URL{
			Scheme: "vless",

			User: url.User(
				connection.UUID,
			),

			Host: net.JoinHostPort(
				host,
				strconv.Itoa(
					connection.Port,
				),
			),

			RawQuery: query.Encode(),

			Fragment: name,
		}

	return value.String(),
		nil
}

func (a *application) listVPNClientConnections(
	w http.ResponseWriter,
	r *http.Request,
) {
	clientID :=
		strings.TrimSpace(
			r.PathValue("id"),
		)

	if clientID == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"client id is required",
		)
		return
	}

	connections, err :=
		a.store.ListVPNClientConnections(
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

	for i := range connections {

		uri, err :=
			buildVPNConnectionURI(
				connections[i],
			)

		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				err.Error(),
			)
			return
		}

		connections[i].URI =
			uri
	}

	writeJSON(
		w,
		http.StatusOK,
		map[string]any{
			"connections": connections,
		},
	)
}

// A client's account name is not the provider's public VPN name.
func vpnConnectionDisplayName(connection model.VPNClientConnection) string {
	return connection.DisplayName()
}
