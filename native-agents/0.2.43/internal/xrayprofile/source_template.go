package xrayprofile

import "encoding/json"

// SourceTemplate is an owner-local export of the reviewed client-free graph.
// Raw private configuration is deliberately excluded from JSON serialization.
// Only an explicit private-file operation may transfer it to its original node.
type SourceTemplate struct {
	InventorySHA256 string                     `json:"inventory_sha256"`
	SourceNodeID    string                     `json:"source_node_id"`
	SourceProfileID string                     `json:"source_profile_id"`
	ConfigSHA256    string                     `json:"config_sha256"`
	Requirements    []SourceInboundRequirement `json:"requirements"`
	Config          []byte                     `json:"-"`
}

func ExportSourceTemplate(raw []byte, nodeID string) (*SourceTemplate, error) {
	source, cfg, tagIDs, active, e := sourceNodeInputs(raw, nodeID)
	if e != nil {
		return nil, e
	}
	config, e := json.Marshal(cfg)
	if e != nil {
		return nil, ErrProfile
	}
	out := &SourceTemplate{InventorySHA256: source.InventorySHA256, SourceNodeID: source.NodeID, SourceProfileID: source.ProfileID, ConfigSHA256: digest(config), Config: config}
	for _, v := range cfg["inbounds"].([]any) {
		in := v.(map[string]any)
		tag := str(in["tag"])
		id := tagIDs[tag]
		out.Requirements = append(out.Requirements, SourceInboundRequirement{ID: id, Tag: tag, Security: str(in["streamSettings"].(map[string]any)["security"]), Enabled: active[id]})
	}
	return out, nil
}
