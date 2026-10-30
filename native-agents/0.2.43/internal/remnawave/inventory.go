// Package remnawave validates read-only inventories without contacting the source.
// Raw inventories contain credentials. Reports deliberately contain counts only.
package remnawave

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxInventoryBytes = 64 << 20
const MaxUsers = 100000
const ContractCommit = "f8ad8ad3410252215ca7b2e429d157bd275ec564"

var ErrInventory = errors.New("invalid or incomplete Remnawave 3.4.3 inventory")
var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type User struct {
	ID                   int64             `json:"id"`
	UUID                 string            `json:"uuid"`
	ShortUUID            string            `json:"shortUuid"`
	Username             string            `json:"username"`
	Status               string            `json:"status"`
	VLESSUUID            string            `json:"vlessUuid"`
	TrojanPassword       string            `json:"trojanPassword"`
	SSPassword           string            `json:"ssPassword"`
	ExpireAt             time.Time         `json:"expireAt"`
	CreatedAt            time.Time         `json:"createdAt"`
	UpdatedAt            time.Time         `json:"updatedAt"`
	TrafficLimitBytes    *int64            `json:"trafficLimitBytes"`
	TrafficLimitStrategy string            `json:"trafficLimitStrategy"`
	HWIDDeviceLimit      *int              `json:"hwidDeviceLimit"`
	SubscriptionURL      string            `json:"subscriptionUrl"`
	InternalSquads       []json.RawMessage `json:"activeInternalSquads"`
	Traffic              struct {
		Used     *int64 `json:"usedTrafficBytes"`
		Lifetime *int64 `json:"lifetimeUsedTrafficBytes"`
	} `json:"userTraffic"`
}

type Inventory struct {
	Format          int               `json:"format"`
	Kind            string            `json:"kind"`
	ContractVersion string            `json:"contract_version"`
	ContractCommit  string            `json:"contract_commit"`
	SourceOrigin    string            `json:"source_origin"`
	StartedAt       time.Time         `json:"started_at"`
	CapturedAt      time.Time         `json:"captured_at"`
	SourceMetadata  json.RawMessage   `json:"source_metadata"`
	Users           []User            `json:"users"`
	Devices         []json.RawMessage `json:"devices"`
	InternalSquads  json.RawMessage   `json:"internal_squads"`
	ExternalSquads  json.RawMessage   `json:"external_squads"`
	Hosts           json.RawMessage   `json:"hosts"`
	Nodes           json.RawMessage   `json:"nodes"`
	ConfigProfiles  json.RawMessage   `json:"config_profiles"`
	Verification    struct {
		SourceTotal               *int `json:"source_total"`
		UniqueUserIDs             *int `json:"unique_user_ids"`
		StableUserPasses          int  `json:"stable_user_passes"`
		StableConfigurationPasses int  `json:"stable_access_configuration_passes"`
		AtomicSnapshot            bool `json:"atomic_database_snapshot"`
	} `json:"verification"`
}

type Report struct {
	SHA256                       string         `json:"sha256"`
	SourceOrigin                 string         `json:"source_origin"`
	ContractVersion              string         `json:"contract_version"`
	CapturedAt                   time.Time      `json:"captured_at"`
	Users                        int            `json:"users"`
	Devices                      int            `json:"devices"`
	StatusCounts                 map[string]int `json:"status_counts"`
	ResetPolicyCounts            map[string]int `json:"reset_policy_counts"`
	LimitedUsers                 int            `json:"limited_users"`
	HWIDLimitedUsers             int            `json:"hwid_limited_users"`
	UsersWithSquads              int            `json:"users_with_squads"`
	SubscriptionURLs             int            `json:"subscription_urls"`
	IndependentTrojanCredentials int            `json:"independent_trojan_credentials"`
	IndependentSSCredentials     int            `json:"independent_ss_credentials"`
	CutoverReady                 bool           `json:"cutover_ready"`
	RequiredReview               []string       `json:"required_review"`
}

// rejectAmbiguity refuses duplicate object fields; otherwise JSON decoders could
// disagree about the reviewed inventory. Also bounds nesting before unmarshalling.
func rejectAmbiguity(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return ErrInventory
		}
		t, err := d.Token()
		if err != nil {
			return ErrInventory
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				s, ok := key.(string)
				if e != nil || !ok || seen[s] {
					return ErrInventory
				}
				seen[s] = true
				if walk(depth+1) != nil {
					return ErrInventory
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrInventory
			}
		case '[':
			for d.More() {
				if walk(depth+1) != nil {
					return ErrInventory
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrInventory
			}
		default:
			return ErrInventory
		}
		return nil
	}
	if walk(0) != nil {
		return ErrInventory
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInventory
	}
	return nil
}

// ValidateSourceJSON applies the same byte and ambiguity checks to companion
// source snapshots before a domain-specific parser validates their contents.
func ValidateSourceJSON(raw []byte, maxBytes int) error {
	if maxBytes <= 0 || len(raw) == 0 || len(raw) > maxBytes || !utf8.Valid(raw) {
		return ErrInventory
	}
	return rejectAmbiguity(raw)
}

func validText(s string, min, max int) bool {
	if !utf8.ValidString(s) || len(s) < min || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func validCount(v *int64) bool { return v != nil && *v >= 0 && *v <= 9007199254740991 }
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null" && (raw[0] == '{' || raw[0] == '[')
}

func Parse(raw []byte) (Inventory, Report, error) {
	var inv Inventory
	var report Report
	if len(raw) == 0 || len(raw) > MaxInventoryBytes || !utf8.Valid(raw) || rejectAmbiguity(raw) != nil || json.Unmarshal(raw, &inv) != nil {
		return inv, report, ErrInventory
	}
	origin, e := url.Parse(inv.SourceOrigin)
	if e != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" || strings.ToLower(origin.Host) != origin.Host {
		return inv, report, ErrInventory
	}
	if inv.Format != 1 || inv.Kind != "remnawave_inventory" || inv.ContractVersion != "3.4.3" || inv.ContractCommit != ContractCommit || inv.StartedAt.IsZero() || inv.CapturedAt.Before(inv.StartedAt) || inv.CapturedAt.After(time.Now().Add(5*time.Minute)) {
		return inv, report, ErrInventory
	}
	if inv.Users == nil || len(inv.Users) > MaxUsers || inv.Devices == nil || len(inv.Devices) > MaxUsers*20 || inv.Verification.SourceTotal == nil || *inv.Verification.SourceTotal != len(inv.Users) || inv.Verification.UniqueUserIDs == nil || *inv.Verification.UniqueUserIDs != len(inv.Users) || inv.Verification.StableUserPasses < 2 || inv.Verification.StableConfigurationPasses < 2 {
		return inv, report, ErrInventory
	}
	for _, v := range []json.RawMessage{inv.SourceMetadata, inv.InternalSquads, inv.ExternalSquads, inv.Hosts, inv.Nodes, inv.ConfigProfiles} {
		if !present(v) {
			return inv, report, ErrInventory
		}
	}
	var metadata struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(inv.SourceMetadata, &metadata) != nil || metadata.Version != "3.4.3" {
		return inv, report, ErrInventory
	}
	digest := sha256.Sum256(raw)
	report = Report{SHA256: hex.EncodeToString(digest[:]), SourceOrigin: inv.SourceOrigin, ContractVersion: inv.ContractVersion, CapturedAt: inv.CapturedAt, Users: len(inv.Users), Devices: len(inv.Devices), StatusCounts: map[string]int{}, ResetPolicyCounts: map[string]int{}, RequiredReview: []string{"source_delta_and_final_freeze", "squads_nodes_hosts_to_target_services", "protocol_credentials_and_endpoint_compatibility", "existing_subscription_urls_and_cutover"}}
	seenID := map[int64]bool{}
	seenShort := map[string]bool{}
	seenUUID := map[string]bool{}
	seenName := map[string]bool{}
	seenSourceUUID := map[string]bool{}
	for _, u := range inv.Users {
		if u.UUID != "" {
			key := strings.ToLower(u.UUID)
			if !uuid.MatchString(key) || seenSourceUUID[key] {
				return inv, Report{}, ErrInventory
			}
			seenSourceUUID[key] = true
		}
		id := strings.ToLower(u.VLESSUUID)
		if u.ID <= 0 || u.ID > 9007199254740991 || seenID[u.ID] || !validText(u.ShortUUID, 1, 256) || seenShort[u.ShortUUID] || !uuid.MatchString(u.VLESSUUID) || seenUUID[id] || !validText(u.Username, 1, 256) || seenName[u.Username] {
			return inv, Report{}, ErrInventory
		}
		seenID[u.ID] = true
		seenShort[u.ShortUUID] = true
		seenUUID[id] = true
		seenName[u.Username] = true
		// The source contract requires timestamps, but does not order them. Imported
		// source history may have an update timestamp earlier than its creation date.
		// Preserve both values rather than rejecting or rewriting valid source data.
		if !validText(u.TrojanPassword, 1, 2048) || !validText(u.SSPassword, 1, 2048) || !validCount(u.TrafficLimitBytes) || !validCount(u.Traffic.Used) || !validCount(u.Traffic.Lifetime) || *u.Traffic.Lifetime < *u.Traffic.Used || u.ExpireAt.IsZero() || u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() || u.InternalSquads == nil {
			return inv, Report{}, ErrInventory
		}
		if u.HWIDDeviceLimit != nil && (*u.HWIDDeviceLimit < 0 || *u.HWIDDeviceLimit > 1000000) {
			return inv, Report{}, ErrInventory
		}
		switch u.Status {
		case "ACTIVE", "DISABLED", "EXPIRED", "LIMITED":
		default:
			return inv, Report{}, ErrInventory
		}
		switch u.TrafficLimitStrategy {
		case "NO_RESET", "DAY", "WEEK", "MONTH", "MONTH_ROLLING":
		default:
			return inv, Report{}, ErrInventory
		}
		sub, e := url.Parse(u.SubscriptionURL)
		if e != nil || sub.Scheme != "https" || sub.Hostname() == "" || sub.User != nil || sub.Fragment != "" || len(u.SubscriptionURL) > 4096 {
			return inv, Report{}, ErrInventory
		}
		report.StatusCounts[u.Status]++
		report.ResetPolicyCounts[u.TrafficLimitStrategy]++
		report.SubscriptionURLs++
		if *u.TrafficLimitBytes > 0 {
			report.LimitedUsers++
		}
		if u.HWIDDeviceLimit != nil && *u.HWIDDeviceLimit > 0 {
			report.HWIDLimitedUsers++
		}
		if len(u.InternalSquads) > 0 {
			report.UsersWithSquads++
		}
		if u.TrojanPassword != u.VLESSUUID {
			report.IndependentTrojanCredentials++
		}
		if u.SSPassword != u.VLESSUUID {
			report.IndependentSSCredentials++
		}
	}
	if report.LimitedUsers > 0 {
		report.RequiredReview = append(report.RequiredReview, "quota_reset_policy_and_used_traffic")
	}
	if report.HWIDLimitedUsers > 0 || report.Devices > 0 {
		report.RequiredReview = append(report.RequiredReview, "hwid_enforcement_and_registered_devices")
	}
	// A valid inventory is ready for held staging, never evidence of a live cutover.
	return inv, report, nil
}
