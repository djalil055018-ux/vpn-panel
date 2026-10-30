package compiler

import (
	"encoding/json"
	"fmt"

	"vpn-platform/internal/model"
	"vpn-platform/internal/xrayprofile"
)

type xrayConfig struct {
	Log       map[string]any `json:"log"`
	API       map[string]any `json:"api"`
	Stats     map[string]any `json:"stats"`
	Policy    map[string]any `json:"policy"`
	Routing   map[string]any `json:"routing"`
	Inbounds  []any          `json:"inbounds"`
	Outbounds []any          `json:"outbounds"`
}

func CompileXray(state model.DesiredState) ([]byte, error) {
	if state.XrayCascades != nil && !xrayprofile.CoreCompatible(state.Core) {
		return nil, ErrXrayCascade
	}
	raw, err := compileXrayBase(state)
	if err != nil {
		return nil, err
	}
	return compileXrayCascades(raw, state)
}

func compileXrayBase(state model.DesiredState) ([]byte, error) {
	if state.XrayProfile != nil {
		if !xrayprofile.CoreCompatible(state.Core) {
			return nil, xrayprofile.ErrProfile
		}
		return xrayprofile.Compile(state.XrayProfile, state.Services)
	}
	cfg := xrayConfig{
		Log: map[string]any{
			"loglevel": "warning",
		},
		API:    map[string]any{"tag": "api", "listen": "127.0.0.1:10085", "services": []string{"StatsService"}},
		Stats:  map[string]any{},
		Policy: map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true}}},
		// Block the management port before destination resolution, including names
		// resolving to loopback. The agent accesses the API directly, outside routing.
		Routing: map[string]any{"rules": []any{map[string]any{
			"type": "field", "port": "10085", "network": "tcp,udp", "outboundTag": "BLOCK",
		}}},

		Inbounds: []any{},

		Outbounds: []any{
			map[string]any{
				"tag":      "DIRECT",
				"protocol": "freedom",
			},
			map[string]any{
				"tag":      "BLOCK",
				"protocol": "blackhole",
			},
		},
	}

	for _, service := range state.Services {
		if service.ID == "" {
			return nil, fmt.Errorf("service id is required")
		}

		if service.Port < 1 || service.Port > 65535 {
			return nil, fmt.Errorf(
				"invalid port for service %s",
				service.ID,
			)
		}
		if service.Port == 10085 {
			return nil, fmt.Errorf("port 10085 is reserved for the local Xray API")
		}

		switch service.Protocol {
		case "wireguard":
			inbound, err := wireguardInbound(service)
			if err != nil {
				return nil, err
			}
			if inbound != nil {
				cfg.Inbounds = append(cfg.Inbounds, inbound)
			}
		case "shadowsocks":
			inbound, err := shadowsocksInbound(service)
			if err != nil {
				return nil, err
			}
			if inbound != nil {
				cfg.Inbounds = append(cfg.Inbounds, inbound)
			}
		case "vless", "trojan":
			if service.Protocol == "trojan" && service.Security != "tls" {
				return nil, fmt.Errorf("Trojan requires TLS")
			}

			if service.Transport != "tcp" && !(model.VLESSTLSTransport(service.Transport) && service.Protocol == "vless" && service.Security == "tls") {
				return nil, fmt.Errorf(
					"unsupported transport: %s",
					service.Transport,
				)
			}

			streamSettings := map[string]any{
				"network":  "tcp",
				"security": "none",
			}
			if service.Transport == "ws" {
				path, ok := model.XHTTPPath(service.ID)
				if !ok {
					return nil, fmt.Errorf("WebSocket requires a service UUID")
				}
				streamSettings["network"] = "ws"
				streamSettings["wsSettings"] = map[string]any{"path": path}
			}
			if service.Transport == "grpc" {
				name, ok := model.GRPCServiceName(service.ID)
				if !ok {
					return nil, fmt.Errorf("gRPC requires a service UUID")
				}
				streamSettings["network"] = "grpc"
				streamSettings["grpcSettings"] = map[string]any{"serviceName": name}
			}
			if service.Transport == "xhttp" {
				path, ok := model.XHTTPPath(service.ID)
				if !ok {
					return nil, fmt.Errorf("XHTTP requires a service UUID")
				}
				streamSettings["network"] = "xhttp"
				streamSettings["xhttpSettings"] = map[string]any{"path": path, "mode": "auto"}
			}

			switch service.Security {
			case "none":
			case "tls":
				if service.TLS == nil || service.TLS.ServerName == "" || service.TLS.CertificateFile == "" || service.TLS.KeyFile == "" {
					return nil, fmt.Errorf("resolved TLS certificate is required for service %s", service.ID)
				}
				streamSettings["security"] = "tls"
				streamSettings["tlsSettings"] = map[string]any{
					"serverName": service.TLS.ServerName,
					"minVersion": "1.2",
					"certificates": []any{map[string]any{
						"certificateFile": service.TLS.CertificateFile,
						"keyFile":         service.TLS.KeyFile,
						"oneTimeLoading":  false,
					}},
				}

			case "reality":
				if service.Reality == nil {
					return nil, fmt.Errorf(
						"reality settings are required for service %s",
						service.ID,
					)
				}

				reality := service.Reality

				if reality.Destination == "" ||
					reality.ServerName == "" ||
					reality.ShortID == "" ||
					reality.PrivateKey == "" {

					return nil, fmt.Errorf(
						"incomplete reality settings for service %s",
						service.ID,
					)
				}

				streamSettings["security"] = "reality"

				streamSettings["realitySettings"] =
					map[string]any{
						"show": false,
						"dest": reality.Destination,
						"xver": 0,
						"serverNames": []string{
							reality.ServerName,
						},
						"privateKey": reality.PrivateKey,
						"shortIds": []string{
							reality.ShortID,
						},
					}

			default:
				return nil, fmt.Errorf(
					"unsupported VLESS security: %s",
					service.Security,
				)
			}

			clients, err := nativeXrayClients(service)
			if err != nil {
				return nil, err
			}

			inbound := map[string]any{
				"tag":      service.ID,
				"listen":   service.Listen,
				"port":     service.Port,
				"protocol": service.Protocol,

				"settings": map[string]any{
					"clients":    clients,
					"decryption": "none",
				},

				"streamSettings": streamSettings,
			}

			if service.Protocol == "trojan" {
				delete(inbound["settings"].(map[string]any), "decryption")
			}
			cfg.Inbounds = append(
				cfg.Inbounds,
				inbound,
			)

		default:
			return nil, fmt.Errorf(
				"unsupported protocol: %s",
				service.Protocol,
			)
		}
	}

	return json.MarshalIndent(
		cfg,
		"",
		"  ",
	)
}
