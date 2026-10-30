package xrayprofile

import (
	"sort"
	"strings"

	"vpn-platform/internal/model"
)

// Dependencies must remain present after native node adoption. They are not
// created or modified by projection/compilation. An owner must verify the actual
// Xray UID can connect to each socket and use each outbound interface.
type Dependencies struct {
	UnixSockets []string `json:"unix_sockets"`
	Interfaces  []string `json:"interfaces"`
}

func RequiredDependencies(spec *model.XrayProfileSpec) (Dependencies, error) {
	cfg, _, err := parse(spec)
	if err != nil {
		return Dependencies{}, err
	}
	return dependenciesFromConfig(cfg), nil
}

func dependenciesFromConfig(cfg map[string]any) Dependencies {
	sockets, interfaces := map[string]bool{}, map[string]bool{}
	for _, value := range cfg["inbounds"].([]any) {
		in := value.(map[string]any)
		stream := in["streamSettings"].(map[string]any)
		if r, ok := stream["realitySettings"].(map[string]any); ok {
			target := str(r["target"])
			if target == "" {
				target = str(r["dest"])
			}
			if strings.HasPrefix(target, "/") {
				sockets[target] = true
			}
		}
	}
	for _, value := range cfg["outbounds"].([]any) {
		out := value.(map[string]any)
		if stream, ok := out["streamSettings"].(map[string]any); ok {
			sock := stream["sockopt"].(map[string]any)
			interfaces[str(sock["interface"])] = true
		}
	}
	result := Dependencies{UnixSockets: []string{}, Interfaces: []string{}}
	for name := range sockets {
		result.UnixSockets = append(result.UnixSockets, name)
	}
	for name := range interfaces {
		result.Interfaces = append(result.Interfaces, name)
	}
	sort.Strings(result.UnixSockets)
	sort.Strings(result.Interfaces)
	return result
}
