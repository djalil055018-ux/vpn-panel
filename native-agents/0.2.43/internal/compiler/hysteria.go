package compiler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"vpn-platform/internal/model"
)

var ErrHysteriaConfig = errors.New("invalid Hysteria runtime configuration")
var hysteriaIdentity = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var hysteriaLocalSecret = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

// HysteriaRuntimeOptions are resolved by the node; they never come from a tenant
// request or subscription. Authentication and traffic management remain local.
type HysteriaRuntimeOptions struct {
	AuthPort, StatisticsPort int
	StatisticsSecret         string
}

func validHysteriaPort(port int) bool { return port >= 1024 && port <= 65535 }
func validHysteriaPath(value string) bool {
	return path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

// CompileHysteria builds one native Hysteria process. The current desired-state
// model chooses one core per node. Reject multiple listeners explicitly until a
// supervised multi-process driver and independent counter epochs are implemented.
// An empty service list is an idle runtime (nil config); an empty client list is
// served by the node-local HTTP authorizer's deny-all snapshot.
func CompileHysteria(state model.DesiredState, options HysteriaRuntimeOptions) ([]byte, error) {
	if err := ValidateHysteriaDesired(state); err != nil {
		return nil, err
	}
	if !validHysteriaPort(options.AuthPort) || !validHysteriaPort(options.StatisticsPort) || options.AuthPort == options.StatisticsPort || !hysteriaLocalSecret.MatchString(options.StatisticsSecret) {
		return nil, ErrHysteriaConfig
	}
	if len(state.Services) == 0 {
		return nil, nil
	}
	s := state.Services[0]
	if s.Port == options.AuthPort || s.Port == options.StatisticsPort || !validHysteriaPath(s.TLS.CertificateFile) || !validHysteriaPath(s.TLS.KeyFile) || s.TLS.CertificateFile == s.TLS.KeyFile {
		return nil, ErrHysteriaConfig
	}
	config := map[string]any{
		"listen":       net.JoinHostPort(s.Listen, strconv.Itoa(s.Port)),
		"tls":          map[string]any{"cert": s.TLS.CertificateFile, "key": s.TLS.KeyFile, "sniGuard": "strict"},
		"auth":         map[string]any{"type": "http", "http": map[string]any{"url": fmt.Sprintf("http://127.0.0.1:%d/auth", options.AuthPort), "insecure": false}},
		"trafficStats": map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", options.StatisticsPort), "secret": options.StatisticsSecret},
		"acl":          map[string]any{"inline": []string{fmt.Sprintf("reject(all, */%d)", options.AuthPort), fmt.Sprintf("reject(all, */%d)", options.StatisticsPort), "direct(all)"}},
	}
	return json.MarshalIndent(config, "", "  ")
}

// ValidateHysteriaDesired validates distributed metadata before a deployment is
// committed. Local certificate paths and management settings belong to the agent
// and are checked separately by CompileHysteria after local resolution.
func ValidateHysteriaDesired(state model.DesiredState) error {
	if state.Core.Type != "hysteria2" || len(state.Services) > 1 {
		return ErrHysteriaConfig
	}
	if len(state.Services) == 0 {
		return nil
	}
	s := state.Services[0]
	if !hysteriaIdentity.MatchString(s.ID) || s.Protocol != "hysteria2" || s.Transport != "udp" || s.Security != "tls" || s.Reality != nil || net.ParseIP(s.Listen) == nil || s.Port < 1 || s.Port > 65535 {
		return ErrHysteriaConfig
	}
	if s.TLS == nil || !hysteriaIdentity.MatchString(s.TLS.CertificateID) || s.TLS.ServerName == "" || strings.ContainsAny(s.TLS.ServerName, " /\\@?#:\x00\r\n") {
		return ErrHysteriaConfig
	}
	ids, credentials := map[string]bool{}, map[string]bool{}
	for _, client := range s.Clients {
		if !hysteriaIdentity.MatchString(client.StatsKey) || client.StatsKey != strings.ToLower(client.StatsKey) || !hysteriaIdentity.MatchString(client.ID) || client.ID != strings.ToLower(client.ID) || ids[client.StatsKey] || credentials[client.ID] {
			return ErrHysteriaConfig
		}
		ids[client.StatsKey] = true
		credentials[client.ID] = true
	}
	return nil
}

// HysteriaURI uses the client's opaque credential with the local HTTP auth
// adapter. No management port/secret or runtime key path enters a subscription.
func HysteriaURI(connection model.VPNClientConnection) (string, error) {
	if connection.Protocol != "hysteria2" || connection.Transport != "udp" || connection.Security != "tls" || !hysteriaIdentity.MatchString(connection.UUID) || connection.UUID != strings.ToLower(connection.UUID) || connection.Port < 1 || connection.Port > 65535 {
		return "", ErrHysteriaConfig
	}
	address := connection.Address
	if address == "" || strings.ContainsAny(address, " /\\@?#\x00\r\n") || strings.HasPrefix(address, "[") || strings.HasSuffix(address, "]") {
		return "", ErrHysteriaConfig
	}
	if strings.Contains(address, ":") && net.ParseIP(address) == nil {
		return "", ErrHysteriaConfig
	}
	if connection.ServerName == "" || strings.ContainsAny(connection.ServerName, " /\\@?#:\x00\r\n") {
		return "", ErrHysteriaConfig
	}
	value := url.URL{Scheme: "hysteria2", User: url.User(connection.UUID), Host: net.JoinHostPort(address, strconv.Itoa(connection.Port)), RawQuery: url.Values{"sni": {connection.ServerName}, "insecure": {"0"}}.Encode(), Fragment: connection.ServiceName}
	return value.String(), nil
}
