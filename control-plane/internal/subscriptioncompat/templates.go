package subscriptioncompat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
	"vpn-platform/internal/remnawave"
)

type Template struct {
	SourceID     string  `json:"source_id"`
	SourceSHA256 string  `json:"source_sha256"`
	Format       string  `json:"format"`
	Body         Options `json:"body"`
}

var decimalYAMLInt = regexp.MustCompile(`^[-+]?(?:0|[1-9][0-9]*)$`)

// parseTemplateYAML allows bounded aliases and merge keys used by the source
// Mihomo template. Duplicate keys, cycles, ambiguous numeric spellings, custom
// tags and multiple documents are rejected before decoding into JSON values.
func parseTemplateYAML(raw []byte) (Options, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return nil, ErrProfile
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if decoder.Decode(&doc) != nil || len(doc.Content) != 1 {
		return nil, ErrProfile
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrProfile
	}
	visits := 0
	active := map[*yaml.Node]bool{}
	var walk func(*yaml.Node, int) bool
	walk = func(n *yaml.Node, depth int) bool {
		visits++
		if n == nil || depth > 48 || visits > 50000 || active[n] {
			return false
		}
		active[n] = true
		defer delete(active, n)
		switch n.Kind {
		case yaml.DocumentNode:
			if len(n.Content) != 1 {
				return false
			}
		case yaml.MappingNode:
			if n.Tag != "!!map" || len(n.Content)%2 != 0 {
				return false
			}
			keys := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || (k.Tag != "!!str" && k.Tag != "!!merge") || keys[k.Value] {
					return false
				}
				keys[k.Value] = true
			}
		case yaml.SequenceNode:
			if n.Tag != "!!seq" {
				return false
			}
		case yaml.AliasNode:
			return walk(n.Alias, depth+1)
		case yaml.ScalarNode:
			switch n.Tag {
			case "!!str", "!!bool", "!!null", "!!merge":
			case "!!int":
				if !decimalYAMLInt.MatchString(n.Value) {
					return false
				}
			case "!!float":
				if strings.Contains(strings.ToLower(n.Value), "inf") || strings.Contains(strings.ToLower(n.Value), "nan") {
					return false
				}
			default:
				return false
			}
		default:
			return false
		}
		for _, child := range n.Content {
			if !walk(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !walk(&doc, 0) {
		return nil, ErrProfile
	}
	var values any
	if doc.Decode(&values) != nil {
		return nil, ErrProfile
	}
	wire, err := json.Marshal(values)
	if err != nil || len(wire) > 4<<20 {
		return nil, ErrProfile
	}
	var out Options
	if json.Unmarshal(wire, &out) != nil || out == nil {
		return nil, ErrProfile
	}
	return out, nil
}
func ProjectTemplates(settings []byte) (map[string]Template, error) {
	out := map[string]Template{}
	if remnawave.ValidateSourceJSON(settings, 16<<20) != nil {
		return nil, ErrProfile
	}
	var snapshot struct {
		Format int    `json:"format"`
		Kind   string `json:"kind"`
		Tables struct {
			Templates []json.RawMessage `json:"subscription_templates"`
		} `json:"tables"`
	}
	if json.Unmarshal(settings, &snapshot) != nil || snapshot.Format != 1 || snapshot.Kind != "remnawave_subscription_settings_snapshot" || len(snapshot.Tables.Templates) != 5 {
		return nil, ErrProfile
	}
	ids := map[string]bool{}
	for _, raw := range snapshot.Tables.Templates {
		if !allowedKeys(raw, "uuid", "name", "tags", "created_at", "updated_at", "view_position", "template_type", "template_json", "template_yaml") {
			return nil, ErrProfile
		}
		var source struct {
			ID     string          `json:"uuid"`
			Name   string          `json:"name"`
			Format string          `json:"template_type"`
			JSON   json.RawMessage `json:"template_json"`
			YAML   *string         `json:"template_yaml"`
		}
		if json.Unmarshal(raw, &source) != nil || !credentialPattern.MatchString(source.ID) || ids[source.ID] || source.Name != "Default" {
			return nil, ErrProfile
		}
		if _, exists := out[source.Format]; exists {
			return nil, ErrProfile
		}
		ids[source.ID] = true
		var body Options
		var sourceBytes []byte
		switch source.Format {
		case "XRAY_JSON", "SINGBOX":
			if source.YAML != nil || len(source.JSON) > 1<<20 || json.Unmarshal(source.JSON, &body) != nil || body == nil {
				return nil, ErrProfile
			}
			sourceBytes = source.JSON
		case "MIHOMO", "STASH", "CLASH":
			if source.YAML == nil || string(source.JSON) != "null" {
				return nil, ErrProfile
			}
			var err error
			sourceBytes = []byte(*source.YAML)
			body, err = parseTemplateYAML(sourceBytes)
			if err != nil {
				return nil, ErrProfile
			}
		default:
			return nil, ErrProfile
		}
		// Exercise template structure even before clients have been activated.
		if _, err := Render([]Host{}, body, source.Format, "11111111-2222-4333-8444-555555555555"); err != nil {
			return nil, ErrProfile
		}
		digest := sha256.Sum256(sourceBytes)
		out[source.Format] = Template{SourceID: source.ID, SourceSHA256: hex.EncodeToString(digest[:]), Format: source.Format, Body: body}
	}
	return out, nil
}
