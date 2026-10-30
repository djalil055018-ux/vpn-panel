package xrayprofile

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"path"
	"strconv"

	"vpn-platform/internal/model"
)

func compatibleService(in map[string]any, service model.ServiceSpec) bool {
	stream := in["streamSettings"].(map[string]any)
	protocol, transport := str(in["protocol"]), str(stream["network"])
	if protocol == "hysteria" {
		protocol, transport = "hysteria2", "udp"
	}
	if transport == "raw" {
		transport = "tcp"
	}
	if service.Protocol != protocol || service.Transport != transport || service.Listen != str(in["listen"]) || strconv.Itoa(service.Port) != strNumber(in["port"]) || service.Security != str(stream["security"]) {
		return false
	}
	if service.Security == "reality" {
		r := stream["realitySettings"].(map[string]any)
		target := str(r["target"])
		if target == "" {
			target = str(r["dest"])
		}
		if service.Reality == nil || service.TLS != nil || service.Reality.SecretRef != "reality/"+service.ID || service.Reality.Destination != target {
			return false
		}
		foundName, foundID := false, false
		for _, value := range r["serverNames"].([]any) {
			foundName = foundName || str(value) == service.Reality.ServerName
		}
		for _, value := range r["shortIds"].([]any) {
			foundID = foundID || str(value) == service.Reality.ShortID
		}
		if !foundName || !foundID {
			return false
		}
	} else {
		if service.TLS == nil || service.Reality != nil || !uuid.MatchString(service.TLS.CertificateID) || service.TLS.ServerName == "" {
			return false
		}
	}
	if service.Shadowsocks != nil || service.WireGuard != nil || service.OpenVPN != nil {
		return false
	}
	ids, stats := map[string]bool{}, map[string]bool{}
	for _, client := range service.Clients {
		if !uuid.MatchString(client.ID) || !uuid.MatchString(client.StatsKey) || ids[client.ID] || stats[client.StatsKey] || client.PPTP != nil || client.WireGuard != nil {
			return false
		}
		ids[client.ID], stats[client.StatsKey] = true, true
	}
	return true
}

func serviceMap(cfg map[string]any, bindings map[string]string, services []model.ServiceSpec) (map[string]model.ServiceSpec, error) {
	byID := map[string]map[string]any{}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		byID[bindings[str(in["tag"])]] = in
	}
	result := map[string]model.ServiceSpec{}
	for _, service := range services {
		in, exists := byID[service.ID]
		_, duplicate := result[service.ID]
		if !exists || duplicate || !compatibleService(in, service) {
			return nil, ErrProfile
		}
		result[service.ID] = service
	}
	return result, nil
}

// Validation on CP deliberately does not require local private material.
func ValidateServices(spec *model.XrayProfileSpec, services []model.ServiceSpec) error {
	cfg, bindings, err := parse(spec)
	if err != nil {
		return err
	}
	_, err = serviceMap(cfg, bindings, services)
	return err
}

// Compile substitutes current authorized clients and resolved local secrets.
// An absent service is disabled: its listener is omitted, not left open with
// a transport-level fallback password. The source routing order is retained.
func Compile(spec *model.XrayProfileSpec, services []model.ServiceSpec) ([]byte, error) {
	cfg, bindings, err := parse(spec)
	if err != nil {
		return nil, err
	}
	byID, err := serviceMap(cfg, bindings, services)
	if err != nil {
		return nil, err
	}
	inbounds := []any{}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		service, enabled := byID[bindings[str(in["tag"])]]
		if !enabled {
			continue
		}
		stream := in["streamSettings"].(map[string]any)
		settings := in["settings"].(map[string]any)
		clients := authorizedClients(in, service)
		delete(settings, "flow")
		settings["clients"] = clients
		if service.Security == "reality" {
			key, err := base64.RawURLEncoding.DecodeString(service.Reality.PrivateKey)
			if err != nil {
				return nil, ErrProfile
			}
			private, err := ecdh.X25519().NewPrivateKey(key)
			if err != nil {
				return nil, ErrProfile
			}
			public := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
			for _, binding := range spec.Bindings {
				if binding.ServiceID == service.ID && binding.RealityPublicKey != public {
					return nil, ErrProfile
				}
			}
			stream["realitySettings"].(map[string]any)["privateKey"] = service.Reality.PrivateKey
		} else {
			if !path.IsAbs(service.TLS.CertificateFile) || !path.IsAbs(service.TLS.KeyFile) {
				return nil, ErrProfile
			}
			stream["tlsSettings"].(map[string]any)["certificates"] = []any{map[string]any{
				"certificateFile": service.TLS.CertificateFile, "keyFile": service.TLS.KeyFile,
				"oneTimeLoading": false,
			}}
		}
		inbounds = append(inbounds, in)
	}
	cfg["inbounds"] = inbounds
	cfg["api"] = map[string]any{"tag": "api", "listen": "127.0.0.1:10085", "services": []string{"StatsService", "HandlerService"}}
	cfg["stats"] = map[string]any{}
	cfg["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true}}}
	cfg["outbounds"] = append(cfg["outbounds"].([]any), map[string]any{"tag": blockTag, "protocol": "blackhole"})
	routing, exists := cfg["routing"].(map[string]any)
	if !exists {
		routing = map[string]any{"rules": []any{}}
		cfg["routing"] = routing
	}
	guard := map[string]any{"type": "field", "port": "10085", "network": "tcp,udp", "outboundTag": blockTag}
	routing["rules"] = append([]any{guard}, routing["rules"].([]any)...)
	return json.MarshalIndent(cfg, "", "  ")
}
