package subscriptioncompat

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"vpn-platform/internal/remnawave"
	"vpn-platform/internal/xrayprofile"
)

type BoundHost struct {
	SourceHostID    string   `json:"source_host_id"`
	SourceProfileID string   `json:"source_profile_id"`
	SourceInboundID string   `json:"source_inbound_id"`
	ServiceIDs      []string `json:"service_ids"`
	Host            Host     `json:"host"`
}
type SquadBinding struct {
	SourceSquadID string   `json:"source_squad_id"`
	ServiceIDs    []string `json:"service_ids"`
}
type Projection struct {
	InventorySHA256 string         `json:"inventory_sha256"`
	Hosts           []BoundHost    `json:"hosts"`
	Squads          []SquadBinding `json:"squads"`
}
type sourceHost struct {
	ID       string `json:"uuid"`
	Name     string `json:"remark"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Position int    `json:"viewPosition"`
	Inbound  struct {
		Profile string `json:"configProfileUuid"`
		ID      string `json:"configProfileInboundUuid"`
	} `json:"inbound"`
	Disabled    *bool             `json:"isDisabled"`
	Hidden      *bool             `json:"isHidden"`
	Shuffle     *bool             `json:"shuffleHost"`
	BlankSNI    *bool             `json:"keepSniBlank"`
	AddressSNI  *bool             `json:"overrideSniFromAddress"`
	X25519      *bool             `json:"mihomoX25519"`
	Security    string            `json:"securityLayer"`
	Fingerprint *string           `json:"fingerprint"`
	ALPN        *string           `json:"alpn"`
	SNI         *string           `json:"sni"`
	Path        *string           `json:"path"`
	Host        *string           `json:"host"`
	Nodes       []json.RawMessage `json:"nodes"`
	Excluded    []string          `json:"excludeFromSubscriptionTypes"`
	Squads      struct {
		Mode string            `json:"mode"`
		IDs  []json.RawMessage `json:"squads"`
	} `json:"internalSquads"`
	Mux         Options `json:"muxParams"`
	Sockopt     Options `json:"sockoptParams"`
	Mapper      Options `json:"mapper"`
	FinalMask   Options `json:"finalMask"`
	XHTTPExtra  Options `json:"xhttpExtraParams"`
	Template    *string `json:"xrayJsonTemplateUuid"`
	PinnedCert  *string `json:"pinnedPeerCertSha256"`
	VerifyName  *string `json:"verifyPeerCertByName"`
	Description *string `json:"serverDescription"`
	IPVersion   *string `json:"mihomoIpVersion"`
	Route       *int    `json:"vlessRouteId"`
}
type projectedInbound struct {
	Config    Options
	Services  []xrayprofile.SourceService
	PublicKey string
}

func nullableText(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
func firstString(v any) string {
	a, _ := v.([]any)
	if len(a) == 0 {
		return ""
	}
	return text(a[0])
}
func sourceMetadataKey(m Options) string { return text(m["profileUuid"]) + "/" + text(m["uuid"]) }
func metadataEqual(a, b Options) bool {
	for _, key := range []string{"uuid", "profileUuid", "tag", "type", "network", "security", "port", "rawInbound"} {
		if !reflect.DeepEqual(a[key], b[key]) {
			return false
		}
	}
	return true
}

// ProjectInventory joins reviewed runtime bindings to source hosts and internal
// squads. Output has no user credentials, source server keys or private paths.
// This is metadata preparation, not permission to serve every projected host.
func ProjectInventory(raw []byte, nodes []*xrayprofile.SourceNodeProjection) (Projection, error) {
	out := Projection{Hosts: []BoundHost{}, Squads: []SquadBinding{}}
	inv, report, err := remnawave.Parse(raw)
	if err != nil || len(nodes) == 0 {
		return out, ErrProfile
	}
	out.InventorySHA256 = report.SHA256
	var inventoryNodes []struct {
		ID string `json:"uuid"`
	}
	if json.Unmarshal(inv.Nodes, &inventoryNodes) != nil || len(inventoryNodes) != len(nodes) {
		return out, ErrProfile
	}
	sourceMetadata := map[string]Options{}
	var profiles struct {
		Profiles []struct {
			ID       string    `json:"uuid"`
			Inbounds []Options `json:"inbounds"`
		} `json:"configProfiles"`
	}
	if json.Unmarshal(inv.ConfigProfiles, &profiles) != nil {
		return out, ErrProfile
	}
	for _, profile := range profiles.Profiles {
		for _, in := range profile.Inbounds {
			key := sourceMetadataKey(in)
			if !credentialPattern.MatchString(text(in["uuid"])) || text(in["profileUuid"]) != profile.ID || sourceMetadata[key] != nil {
				return out, ErrProfile
			}
			sourceMetadata[key] = in
		}
	}
	byInbound := map[string]*projectedInbound{}
	knownNodes := map[string]bool{}
	knownServices := map[string]bool{}
	for _, node := range nodes {
		if node == nil || node.Profile == nil || xrayprofile.Validate(node.Profile) != nil || knownNodes[node.NodeID] || node.InventorySHA256 != report.SHA256 {
			return out, ErrProfile
		}
		knownNodes[node.NodeID] = true
		assignments := []xrayprofile.SourceServiceAssignment{}
		for _, s := range node.Services {
			if knownServices[s.Service.ID] {
				return out, ErrProfile
			}
			knownServices[s.Service.ID] = true
			assignments = append(assignments, xrayprofile.SourceServiceAssignment{InboundID: s.InboundID, ServiceID: s.Service.ID, TLS: s.Service.TLS})
		}
		verified, e := xrayprofile.ProjectSourceNode(raw, node.NodeID, assignments)
		if e != nil || verified.Profile.SHA256 != node.Profile.SHA256 || !reflect.DeepEqual(verified.Services, node.Services) || node.ProfileID != verified.ProfileID {
			return out, ErrProfile
		}
		// Use the freshly validated projection, never caller-supplied raw graph bytes.
		var config Options
		if json.Unmarshal(verified.Profile.Config, &config) != nil {
			return out, ErrProfile
		}
		byTag := map[string]Options{}
		for _, v := range config["inbounds"].([]any) {
			in := object(v)
			byTag[text(in["tag"])] = in
		}
		for _, s := range verified.Services {
			key := verified.ProfileID + "/" + s.InboundID
			if sourceMetadata[key] == nil {
				return out, ErrProfile
			}
			public := ""
			for _, b := range verified.Profile.Bindings {
				if b.ServiceID == s.Service.ID {
					public = b.RealityPublicKey
				}
			}
			entry := byInbound[key]
			if entry == nil {
				entry = &projectedInbound{Config: byTag[s.InboundTag], PublicKey: public}
				byInbound[key] = entry
			}
			if entry.PublicKey != public || !reflect.DeepEqual(entry.Config, byTag[s.InboundTag]) {
				return out, ErrProfile
			}
			entry.Services = append(entry.Services, s)
		}
	}
	// Squad inbound references must be exactly the selected source metadata.
	for _, node := range inventoryNodes {
		if !knownNodes[node.ID] {
			return out, ErrProfile
		}
	}
	var squads struct {
		Squads []struct {
			ID       string    `json:"uuid"`
			Inbounds []Options `json:"inbounds"`
		} `json:"internalSquads"`
	}
	if json.Unmarshal(inv.InternalSquads, &squads) != nil || squads.Squads == nil {
		return out, ErrProfile
	}
	knownSquads := map[string]bool{}
	for _, s := range squads.Squads {
		if !credentialPattern.MatchString(s.ID) || knownSquads[s.ID] || s.Inbounds == nil {
			return out, ErrProfile
		}
		knownSquads[s.ID] = true
		binding := SquadBinding{SourceSquadID: s.ID, ServiceIDs: []string{}}
		seen := map[string]bool{}
		for _, in := range s.Inbounds {
			key := sourceMetadataKey(in)
			entry := byInbound[key]
			if entry == nil || seen[key] || !metadataEqual(in, sourceMetadata[key]) {
				return out, ErrProfile
			}
			seen[key] = true
			for _, service := range entry.Services {
				binding.ServiceIDs = append(binding.ServiceIDs, service.Service.ID)
			}
		}
		sort.Strings(binding.ServiceIDs)
		out.Squads = append(out.Squads, binding)
	}
	var hosts []sourceHost
	if json.Unmarshal(inv.Hosts, &hosts) != nil || hosts == nil || len(hosts) > 1000 {
		return out, ErrProfile
	}
	sort.SliceStable(hosts, func(i, j int) bool { return hosts[i].Position < hosts[j].Position })
	knownHosts, positions := map[string]bool{}, map[int]bool{}
	names := map[string]int{}
	for _, source := range hosts {
		if !credentialPattern.MatchString(source.ID) || knownHosts[source.ID] || positions[source.Position] || source.Position < 0 {
			return out, ErrProfile
		}
		knownHosts[source.ID] = true
		positions[source.Position] = true
		if source.Disabled == nil || source.Hidden == nil || source.Shuffle == nil || source.BlankSNI == nil || source.AddressSNI == nil || source.X25519 == nil {
			return out, ErrProfile
		}
		if *source.Shuffle || *source.BlankSNI || *source.AddressSNI || *source.X25519 || source.Security != "DEFAULT" || source.Route != nil || source.IPVersion != nil || source.Description != nil ||
			source.Template != nil || source.PinnedCert != nil || source.VerifyName != nil || len(source.Nodes) > 0 || source.Squads.Mode != "EXCLUDE" || len(source.Squads.IDs) > 0 ||
			len(source.Mapper) > 0 || len(source.FinalMask) > 0 || len(source.XHTTPExtra) > 0 {
			return out, ErrProfile
		}
		// The current review has no host overrides/randomization or user templates.
		for _, v := range []*string{source.SNI, source.Path, source.Host, source.ALPN} {
			if nullableText(v) != "" {
				return out, ErrProfile
			}
		}
		if strings.ContainsAny(source.Name, "{}") || strings.ContainsAny(source.Address, ",*") {
			return out, ErrProfile
		}
		entry := byInbound[source.Inbound.Profile+"/"+source.Inbound.ID]
		if entry == nil {
			return out, ErrProfile
		}
		in := entry.Config
		stream := object(in["streamSettings"])
		h := Host{Name: source.Name, Address: source.Address, Port: source.Port, Protocol: text(in["protocol"]), Transport: text(stream["network"]), Security: text(stream["security"]),
			ProtocolOptions: Options{}, TransportOptions: Options{}, SecurityOptions: Options{}, Mux: copyObject(source.Mux)}
		h.Metadata.Disabled = *source.Disabled
		h.Metadata.Hidden = *source.Hidden
		h.Metadata.Excluded = append([]string{}, source.Excluded...)
		h.Client.Mapper = Options{}
		for _, f := range h.Metadata.Excluded {
			switch f {
			case "XRAY_BASE64", "XRAY_JSON", "SINGBOX", "MIHOMO", "STASH", "CLASH":
			default:
				return out, ErrProfile
			}
		}
		if count := names[h.Name]; count > 0 {
			suffix := count + 1
			if strings.Contains(h.Name, "^~") && strings.HasSuffix(h.Name, "~^") {
				suffix = count
			}
			h.Name += " ^~" + strconv.Itoa(suffix) + "~^"
		}
		names[source.Name]++
		if h.Protocol == "vless" {
			flow := ""
			settings := object(in["settings"])
			if value, exists := settings["flow"]; exists {
				if value == "xtls-rprx-vision" {
					flow = "xtls-rprx-vision"
				}
			} else if h.Transport == "tcp" || h.Transport == "raw" {
				flow = "xtls-rprx-vision"
			}
			h.ProtocolOptions = Options{"encryption": "none", "flow": flow}
		} else {
			h.ProtocolOptions = Options{"version": 2}
		}
		switch h.Transport {
		case "raw", "tcp":
			h.Transport = "tcp"
			h.TransportOptions = Options{"header": nil}
		case "grpc":
			g := object(stream["grpcSettings"])
			h.TransportOptions = Options{"authority": "", "serviceName": g["serviceName"], "multiMode": truth(g["multiMode"])}
		case "xhttp":
			x := object(stream["xhttpSettings"])
			h.TransportOptions = Options{"host": valueOr(x["host"], ""), "path": x["path"], "mode": valueOr(x["mode"], "auto"), "extra": x["extra"]}
		case "hysteria":
			h.TransportOptions = Options{"version": 2}
		default:
			return out, ErrProfile
		}
		fp := nullableText(source.Fingerprint)
		if fp == "" {
			fp = "chrome"
		}
		if h.Security == "reality" {
			r := object(stream["realitySettings"])
			h.SecurityOptions = Options{"fingerprint": fp, "publicKey": entry.PublicKey, "serverName": firstString(r["serverNames"]), "shortId": firstString(r["shortIds"]), "spiderX": valueOr(r["spiderX"], ""), "mldsa65Verify": nil}
		} else {
			tls := object(stream["tlsSettings"])
			sni := text(tls["serverName"])
			if sni == "" {
				sni = h.Address
			}
			values := []string{}
			if a, ok := tls["alpn"].([]any); ok {
				for _, v := range a {
					values = append(values, text(v))
				}
			}
			h.SecurityOptions = Options{"fingerprint": fp, "serverName": sni, "alpn": strings.Join(values, ","), "enableSessionResumption": truth(tls["enableSessionResumption"]), "echConfigList": nil, "echForceQuery": nil, "echSockopt": nil, "pinnedPeerCertSha256": nil, "verifyPeerCertByName": nil, "cipherSuites": nil}
			for _, s := range entry.Services {
				if s.Service.TLS == nil || s.Service.TLS.ServerName != sni {
					return out, ErrProfile
				}
			}
		}
		h.Stream.Sockopt = copyObject(source.Sockopt)
		h.Stream.FinalMask = object(clone(stream["finalmask"]))
		if !validHost(h) {
			return out, ErrProfile
		}
		bound := BoundHost{SourceHostID: source.ID, SourceProfileID: source.Inbound.Profile, SourceInboundID: source.Inbound.ID, ServiceIDs: []string{}, Host: h}
		for _, s := range entry.Services {
			if s.Enabled {
				bound.ServiceIDs = append(bound.ServiceIDs, s.Service.ID)
			}
		}
		if len(bound.ServiceIDs) == 0 && !h.Metadata.Disabled {
			return out, ErrProfile
		}
		sort.Strings(bound.ServiceIDs)
		out.Hosts = append(out.Hosts, bound)
	}
	return out, nil
}
