package xrayprofile

import (
	"bytes"
	"encoding/json"
	"strconv"

	"vpn-platform/internal/model"
	"vpn-platform/internal/remnawave"
)

// Assignments are supplied by the owner preparation transaction. They contain
// native identities, never executable config, keys, client membership or paths.
type SourceServiceAssignment struct {
	InboundID string
	ServiceID string
	TLS       *model.TLSSpec
}

type SourceService struct {
	InboundID  string            `json:"source_inbound_id"`
	InboundTag string            `json:"inbound_tag"`
	Enabled    bool              `json:"source_enabled"`
	Service    model.ServiceSpec `json:"service"`
}

type SourceNodeProjection struct {
	InventorySHA256 string                 `json:"inventory_sha256"`
	NodeID          string                 `json:"source_node_id"`
	ProfileID       string                 `json:"source_profile_id"`
	Profile         *model.XrayProfileSpec `json:"profile"`
	Services        []SourceService        `json:"services"`
}

type sourceInbound struct {
	ID        string          `json:"uuid"`
	ProfileID string          `json:"profileUuid"`
	Tag       string          `json:"tag"`
	Protocol  string          `json:"type"`
	Network   string          `json:"network"`
	Security  string          `json:"security"`
	Port      int             `json:"port"`
	Raw       json.RawMessage `json:"rawInbound"`
}
type sourceNode struct {
	ID             string          `json:"uuid"`
	Disabled       *bool           `json:"isDisabled"`
	Plugin         json.RawMessage `json:"activePluginUuid"`
	Proxy          json.RawMessage `json:"proxyUrl"`
	Multiplier     *float64        `json:"consumptionMultiplier"`
	NodeMultiplier *float64        `json:"nodeConsumptionMultiplier"`
	Config         struct {
		ProfileID string          `json:"activeConfigProfileUuid"`
		Inbounds  []sourceInbound `json:"activeInbounds"`
	} `json:"configProfile"`
}
type sourceProfile struct {
	ID       string          `json:"uuid"`
	Config   json.RawMessage `json:"config"`
	Inbounds []sourceInbound `json:"inbounds"`
	Nodes    []struct {
		ID string `json:"uuid"`
	} `json:"nodes"`
}

func matchingSourceInbound(value sourceInbound, profileID string, in map[string]any) bool {
	if !uuid.MatchString(value.ID) || value.ProfileID != profileID {
		return false
	}
	raw, err := decode(value.Raw)
	if err != nil {
		return false
	}
	actual, _ := json.Marshal(raw)
	expected, _ := json.Marshal(in)
	if !bytes.Equal(actual, expected) {
		return false
	}
	stream, ok := in["streamSettings"].(map[string]any)
	if !ok {
		return false
	}
	return value.Tag == str(in["tag"]) && value.Protocol == str(in["protocol"]) &&
		value.Network == str(stream["network"]) && value.Security == str(stream["security"]) &&
		strconv.Itoa(value.Port) == strNumber(in["port"])
}

// ProjectSourceNode accepts the exact private source snapshot, verifies all
// node/profile/inbound cross-references, and returns only a public projection.
// It does not activate anything or return source server/client private material.
func sourceNodeInputs(raw []byte, nodeID string) (*SourceNodeProjection, map[string]any, map[string]string, map[string]bool, error) {
	invalid := func() (*SourceNodeProjection, map[string]any, map[string]string, map[string]bool, error) {
		return nil, nil, nil, nil, ErrProfile
	}
	inventory, report, err := remnawave.Parse(raw)
	if err != nil || !uuid.MatchString(nodeID) {
		return invalid()
	}
	var nodes []sourceNode
	var profiles struct {
		Profiles []sourceProfile `json:"configProfiles"`
	}
	if json.Unmarshal(inventory.Nodes, &nodes) != nil || json.Unmarshal(inventory.ConfigProfiles, &profiles) != nil {
		return invalid()
	}
	seen := map[string]bool{}
	var node *sourceNode
	for i := range nodes {
		candidate := &nodes[i]
		if !uuid.MatchString(candidate.ID) || seen[candidate.ID] {
			return invalid()
		}
		seen[candidate.ID] = true
		if candidate.ID == nodeID {
			node = candidate
		}
	}
	// These source features would change routing/accounting semantics; the current
	// adoption contract intentionally has no implicit default or approximation.
	if node == nil || node.Disabled == nil || *node.Disabled || !bytes.Equal(bytes.TrimSpace(node.Plugin), []byte("null")) || !bytes.Equal(bytes.TrimSpace(node.Proxy), []byte("null")) ||
		node.Multiplier == nil || *node.Multiplier != 1 || node.NodeMultiplier == nil || *node.NodeMultiplier != 1 || node.Config.Inbounds == nil {
		return invalid()
	}
	seen = map[string]bool{}
	var selected *sourceProfile
	for i := range profiles.Profiles {
		p := &profiles.Profiles[i]
		if !uuid.MatchString(p.ID) || seen[p.ID] {
			return invalid()
		}
		seen[p.ID] = true
		if p.ID == node.Config.ProfileID {
			selected = p
		}
	}
	if selected == nil {
		return invalid()
	}
	referenced := false
	seen = map[string]bool{}
	for _, n := range selected.Nodes {
		if !uuid.MatchString(n.ID) || seen[n.ID] {
			return invalid()
		}
		seen[n.ID] = true
		if n.ID == nodeID {
			referenced = true
		}
	}
	if !referenced {
		return invalid()
	}
	config, err := decode(selected.Config)
	if err != nil || validateConfig(config, true) != nil {
		return invalid()
	}
	inbounds := config["inbounds"].([]any)
	if len(selected.Inbounds) != len(inbounds) {
		return invalid()
	}
	byTag := map[string]map[string]any{}
	for _, value := range inbounds {
		in := value.(map[string]any)
		byTag[str(in["tag"])] = in
	}
	metadata := map[string]sourceInbound{}
	tagIDs := map[string]string{}
	for _, in := range selected.Inbounds {
		if _, exists := metadata[in.ID]; exists {
			return invalid()
		}
		cfg, ok := byTag[in.Tag]
		if !ok || tagIDs[in.Tag] != "" || !matchingSourceInbound(in, selected.ID, cfg) {
			return invalid()
		}
		metadata[in.ID] = in
		tagIDs[in.Tag] = in.ID
	}
	active := map[string]bool{}
	for _, in := range node.Config.Inbounds {
		expected, ok := metadata[in.ID]
		if !ok || active[in.ID] || expected.Tag != in.Tag || !matchingSourceInbound(in, selected.ID, byTag[in.Tag]) {
			return invalid()
		}
		active[in.ID] = true
	}
	return &SourceNodeProjection{InventorySHA256: report.SHA256, NodeID: nodeID, ProfileID: selected.ID, Services: []SourceService{}}, config, tagIDs, active, nil
}

// Requirements exposes only the identities necessary to assign native services
// and certificates. It uses the same source validation as the final projection.
type SourceInboundRequirement struct {
	ID       string `json:"source_inbound_id"`
	Tag      string `json:"inbound_tag"`
	Security string `json:"security"`
	Enabled  bool   `json:"source_enabled"`
}

func SourceNodeRequirements(raw []byte, nodeID string) ([]SourceInboundRequirement, error) {
	_, config, tagIDs, active, err := sourceNodeInputs(raw, nodeID)
	if err != nil {
		return nil, err
	}
	out := []SourceInboundRequirement{}
	for _, value := range config["inbounds"].([]any) {
		in := value.(map[string]any)
		tag := str(in["tag"])
		id := tagIDs[tag]
		out = append(out, SourceInboundRequirement{ID: id, Tag: tag, Security: str(in["streamSettings"].(map[string]any)["security"]), Enabled: active[id]})
	}
	return out, nil
}

func ProjectSourceNode(raw []byte, nodeID string, assignments []SourceServiceAssignment) (*SourceNodeProjection, error) {
	out, config, tagIDs, active, err := sourceNodeInputs(raw, nodeID)
	if err != nil {
		return nil, err
	}
	inbounds := config["inbounds"].([]any)
	if len(assignments) != len(inbounds) {
		return nil, ErrProfile
	}
	metadata := map[string]bool{}
	for _, id := range tagIDs {
		metadata[id] = true
	}
	byInbound := map[string]SourceServiceAssignment{}
	for _, a := range assignments {
		if !metadata[a.InboundID] || byInbound[a.InboundID].ServiceID != "" || !uuid.MatchString(a.ServiceID) {
			return nil, ErrProfile
		}
		if a.TLS != nil && (a.TLS.CertificateFile != "" || a.TLS.KeyFile != "") {
			return nil, ErrProfile
		}
		byInbound[a.InboundID] = a
	}
	bindings := []model.XrayProfileBinding{}
	definitions := []model.ServiceSpec{}
	for _, value := range inbounds {
		in := value.(map[string]any)
		tag := str(in["tag"])
		inboundID := tagIDs[tag]
		a := byInbound[inboundID]
		stream := in["streamSettings"].(map[string]any)
		protocol, transport := str(in["protocol"]), str(stream["network"])
		if protocol == "hysteria" {
			protocol, transport = "hysteria2", "udp"
		}
		if transport == "raw" {
			transport = "tcp"
		}
		port, _ := strconv.Atoi(strNumber(in["port"]))
		service := model.ServiceSpec{ID: a.ServiceID, Protocol: protocol, Listen: str(in["listen"]), Port: port, Transport: transport, Security: str(stream["security"])}
		if service.Security == "reality" {
			if a.TLS != nil {
				return nil, ErrProfile
			}
			r := stream["realitySettings"].(map[string]any)
			target := str(r["target"])
			if target == "" {
				target = str(r["dest"])
			}
			service.Reality = &model.RealitySpec{Destination: target, ServerName: str(r["serverNames"].([]any)[0]), ShortID: str(r["shortIds"].([]any)[0]), Fingerprint: "chrome", SecretRef: "reality/" + a.ServiceID}
		} else {
			if a.TLS == nil {
				return nil, ErrProfile
			}
			certificate := *a.TLS
			service.TLS = &certificate
		}
		bindings = append(bindings, model.XrayProfileBinding{ServiceID: a.ServiceID, InboundTag: tag})
		out.Services = append(out.Services, SourceService{InboundID: inboundID, InboundTag: tag, Enabled: active[inboundID], Service: service})
		definitions = append(definitions, service)
	}
	configRaw, _ := json.Marshal(config)
	out.Profile, _, err = Project(configRaw, bindings)
	if err != nil || ValidateServices(out.Profile, definitions) != nil {
		return nil, ErrProfile
	}
	return out, nil
}
