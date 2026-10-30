package subscriptioncompat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
	"vpn-platform/internal/remnawave"
)

type PolicyProjection struct {
	InventorySHA256 string            `json:"inventory_sha256"`
	SettingsSHA256  string            `json:"settings_sha256"`
	Global          Policy            `json:"global"`
	External        map[string]Policy `json:"external"`
	// Account association is separate from the public policy, never inferred from
	// a matching username or Telegram ID. Store preparation uses source numeric ID.
	UserExternal map[int64]string           `json:"-"`
	Pages        map[string]json.RawMessage `json:"pages"`
	PageDetails  map[string]PageMetadata    `json:"page_details"`
}

type PageMetadata struct {
	ID           string `json:"uuid"`
	Name         string `json:"name"`
	ViewPosition int    `json:"viewPosition"`
}
type PageConfig struct {
	PageMetadata
	Config json.RawMessage `json:"config"`
}

func allowedKeys(raw json.RawMessage, keys ...string) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return false
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range obj {
		if !allowed[key] {
			return false
		}
	}
	return true
}
func validateRuleDocument(raw json.RawMessage) bool {
	if !allowedKeys(raw, "version", "rules", "settings") {
		return false
	}
	var top struct {
		Rules    []json.RawMessage `json:"rules"`
		Settings json.RawMessage   `json:"settings"`
	}
	if json.Unmarshal(raw, &top) != nil {
		return false
	}
	if len(top.Settings) > 0 && string(top.Settings) != "null" {
		if !allowedKeys(top.Settings, "disableSubscriptionAccessByPath") {
			return false
		}
	}
	for _, r := range top.Rules {
		if !allowedKeys(r, "name", "description", "enabled", "operator", "conditions", "responseType", "responseModifications") {
			return false
		}
		var entry struct {
			Conditions []json.RawMessage `json:"conditions"`
		}
		if json.Unmarshal(r, &entry) != nil {
			return false
		}
		for _, c := range entry.Conditions {
			if !allowedKeys(c, "headerName", "operator", "value", "caseSensitive") {
				return false
			}
		}
	}
	return true
}

// ProjectPolicies preserves the public policy of each source external squad,
// including remove-then-add headers and browser page identity. Native access
// decisions and browser page rendering are intentionally separate consumers.
func ProjectPolicies(inventory, settings []byte) (PolicyProjection, error) {
	out := PolicyProjection{External: map[string]Policy{}, UserExternal: map[int64]string{}, Pages: map[string]json.RawMessage{}, PageDetails: map[string]PageMetadata{}}
	inv, report, err := remnawave.Parse(inventory)
	if err != nil || remnawave.ValidateSourceJSON(settings, 16<<20) != nil {
		return out, ErrProfile
	}
	var source struct {
		Format   int                          `json:"format"`
		Kind     string                       `json:"kind"`
		Origin   string                       `json:"source_origin"`
		Captured time.Time                    `json:"captured_at"`
		Tables   map[string][]json.RawMessage `json:"tables"`
	}
	if !allowedKeys(settings, "format", "kind", "source_origin", "captured_at", "tables") || json.Unmarshal(settings, &source) != nil ||
		source.Format != 1 || source.Kind != "remnawave_subscription_settings_snapshot" || source.Origin != inv.SourceOrigin || source.Captured.IsZero() || source.Captured.After(time.Now().Add(5*time.Minute)) ||
		len(source.Tables["subscription_settings"]) != 1 || len(source.Tables["subscription_page_config"]) != 1 {
		return out, ErrProfile
	}
	for name, rows := range source.Tables {
		switch name {
		case "subscription_settings", "subscription_page_config", "subscription_templates":
		default:
			if len(rows) != 0 {
				return out, ErrProfile
			}
		}
	}
	raw := source.Tables["subscription_settings"][0]
	if !allowedKeys(raw, "uuid", "created_at", "updated_at", "custom_remarks", "custom_response_headers", "hwid_settings", "is_show_custom_remarks", "randomize_hosts", "response_rules", "serve_json_at_base_subscription") {
		return out, ErrProfile
	}
	var globals struct {
		Remarks   map[string][]string `json:"custom_remarks"`
		Headers   map[string]string   `json:"custom_response_headers"`
		HWID      HWIDPolicy          `json:"hwid_settings"`
		Show      *bool               `json:"is_show_custom_remarks"`
		Random    *bool               `json:"randomize_hosts"`
		Rules     json.RawMessage     `json:"response_rules"`
		ServeJSON *bool               `json:"serve_json_at_base_subscription"`
	}
	if json.Unmarshal(raw, &globals) != nil || globals.Show == nil || globals.Random == nil || *globals.Random || globals.ServeJSON == nil || !validateRuleDocument(globals.Rules) {
		return out, ErrProfile
	}
	// Reject new HWID controls instead of silently ignoring source enforcement.
	var globalMap map[string]json.RawMessage
	if json.Unmarshal(raw, &globalMap) != nil || !allowedKeys(globalMap["hwid_settings"], "enabled", "fallbackDeviceLimit", "maxDevicesAnnounce") {
		return out, ErrProfile
	}
	out.Global = Policy{Headers: globals.Headers, Remarks: globals.Remarks, HWID: globals.HWID, ShowRemarks: *globals.Show, ServeJSON: *globals.ServeJSON}
	if json.Unmarshal(globals.Rules, &out.Global.Rules) != nil {
		return out, ErrProfile
	}
	for _, rawPage := range source.Tables["subscription_page_config"] {
		var page struct {
			ID           string          `json:"uuid"`
			Config       json.RawMessage `json:"config"`
			Name         string          `json:"name"`
			ViewPosition *int            `json:"view_position"`
		}
		if json.Unmarshal(rawPage, &page) != nil || !credentialPattern.MatchString(page.ID) || len(page.Config) == 0 || page.Config[0] != '{' ||
			page.Name == "" || !validPublicText(page.Name, 512) || page.ViewPosition == nil || *page.ViewPosition < 0 || *page.ViewPosition > 100000 {
			return out, ErrProfile
		}
		out.Pages[page.ID] = append(json.RawMessage(nil), page.Config...)
		out.PageDetails[page.ID] = PageMetadata{ID: page.ID, Name: page.Name, ViewPosition: *page.ViewPosition}
		id := page.ID
		out.Global.PageID = &id
	}
	if out.Global.Validate() != nil {
		return out, ErrProfile
	}
	var external struct {
		Squads []json.RawMessage `json:"externalSquads"`
	}
	if json.Unmarshal(inv.ExternalSquads, &external) != nil || external.Squads == nil {
		return out, ErrProfile
	}
	for _, rawExternal := range external.Squads {
		if !allowedKeys(rawExternal, "uuid", "name", "createdAt", "updatedAt", "viewPosition", "tags", "info", "customRemarks", "hostOverrides", "hwidSettings", "responseHeadersAdd", "responseHeadersRemove", "subpageConfigUuid", "subscriptionSettings", "templates") {
			return out, ErrProfile
		}
		var s struct {
			ID        string              `json:"uuid"`
			Host      Options             `json:"hostOverrides"`
			Settings  Options             `json:"subscriptionSettings"`
			Templates []json.RawMessage   `json:"templates"`
			HWID      *HWIDPolicy         `json:"hwidSettings"`
			Remarks   map[string][]string `json:"customRemarks"`
			Add       map[string]string   `json:"responseHeadersAdd"`
			Remove    []string            `json:"responseHeadersRemove"`
			PageID    *string             `json:"subpageConfigUuid"`
		}
		if json.Unmarshal(rawExternal, &s) != nil || !credentialPattern.MatchString(s.ID) || len(s.Host) > 0 || len(s.Settings) > 0 || len(s.Templates) > 0 {
			return out, ErrProfile
		}
		if _, exists := out.External[s.ID]; exists {
			return out, ErrProfile
		}
		if s.PageID != nil && out.Pages[*s.PageID] == nil {
			return out, ErrProfile
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(rawExternal, &fields) != nil {
			return out, ErrProfile
		}
		if s.HWID != nil && !allowedKeys(fields["hwidSettings"], "enabled", "fallbackDeviceLimit", "maxDevicesAnnounce") {
			return out, ErrProfile
		}
		patched, e := out.Global.OverlayExternal(s.Remove, s.Add, s.Remarks, s.HWID, s.PageID)
		if e != nil {
			return out, ErrProfile
		}
		out.External[s.ID] = patched
	}
	var users struct {
		Users []struct {
			ID       int64   `json:"id"`
			External *string `json:"externalSquadUuid"`
		} `json:"users"`
	}
	if json.Unmarshal(inventory, &users) != nil || len(users.Users) != len(inv.Users) {
		return out, ErrProfile
	}
	for i, u := range users.Users {
		if u.ID != inv.Users[i].ID {
			return out, ErrProfile
		}
		if u.External != nil {
			if _, ok := out.External[*u.External]; !ok {
				return out, ErrProfile
			}
			out.UserExternal[u.ID] = *u.External
		}
	}
	digest := sha256.Sum256(settings)
	out.SettingsSHA256 = hex.EncodeToString(digest[:])
	out.InventorySHA256 = report.SHA256
	return out, nil
}
