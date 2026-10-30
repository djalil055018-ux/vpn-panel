// Package botbridge implements the private, tenant-scoped bot migration contract.
package botbridge

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
	"vpn-platform/internal/remnawave"
)

var ErrInventory = errors.New("source metadata cannot be represented by bot contract v1")
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

type UserMetadata struct {
	ID              int64     `json:"id"`
	Username        string    `json:"username"`
	TelegramID      *int64    `json:"telegramId"`
	Email           *string   `json:"email"`
	Description     *string   `json:"description"`
	HWIDDeviceLimit *int      `json:"hwidDeviceLimit"`
	LifetimeBytes   int64     `json:"lifetimeUsedTrafficBytes"`
	CreatedAt       time.Time `json:"createdAt"`
	SquadIDs        []string  `json:"squadIds"`
	// Subscription bearer material is used only by private preparation, never
	// accidentally included when a metadata object is marshaled into a report.
	ShortUUID string `json:"-"`
}
type Squad struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}
type Device struct {
	UserID    int64     `json:"userId"`
	HWID      string    `json:"hwid"`
	Platform  *string   `json:"platform"`
	OSVersion *string   `json:"osVersion"`
	Model     *string   `json:"deviceModel"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
type Inventory struct {
	SHA256           string
	CapturedAt       time.Time
	SubscriptionBase string
	Users            []UserMetadata
	Squads           []Squad
	Devices          []Device
}

func bounded(value *string, max int) bool {
	if value == nil {
		return true
	}
	if !utf8.ValidString(*value) || len(*value) > max {
		return false
	}
	for _, c := range *value {
		if c == 0 || c == 127 {
			return false
		}
	}
	return true
}

// ParseMetadata first uses the existing full credential inventory validator.
// It then projects a narrow allowlist for bot use. Original bytes remain in the
// immutable private import history; unknown source fields are never served.
func ParseMetadata(raw []byte) (Inventory, error) {
	out := Inventory{Users: []UserMetadata{}, Squads: []Squad{}, Devices: []Device{}}
	source, report, err := remnawave.Parse(raw)
	if err != nil {
		return out, ErrInventory
	}
	var extra struct {
		Users []UserMetadata `json:"users"`
	}
	if json.Unmarshal(raw, &extra) != nil || len(extra.Users) != len(source.Users) {
		return out, ErrInventory
	}
	var squads struct {
		Squads []Squad `json:"internalSquads"`
	}
	if json.Unmarshal(source.InternalSquads, &squads) != nil || squads.Squads == nil {
		return out, ErrInventory
	}
	knownSquads := map[string]bool{}
	for _, s := range squads.Squads {
		s.UUID = strings.ToLower(s.UUID)
		if !uuidPattern.MatchString(s.UUID) || knownSquads[s.UUID] || strings.TrimSpace(s.Name) == "" || !bounded(&s.Name, 256) {
			return out, ErrInventory
		}
		knownSquads[s.UUID] = true
		out.Squads = append(out.Squads, s)
	}
	knownUsers := map[int64]bool{}
	for i, u := range source.Users {
		m := extra.Users[i]
		if m.ID != u.ID || u.TrafficLimitStrategy != "NO_RESET" || u.Traffic.Lifetime == nil || *u.Traffic.Lifetime < 0 || *u.Traffic.Lifetime > 9000000000000000 || !aliasPattern.MatchString(u.ShortUUID) {
			return out, ErrInventory
		}
		if m.TelegramID != nil && (*m.TelegramID < 0 || *m.TelegramID > 9007199254740991) || !bounded(m.Email, 320) || !bounded(m.Description, 4096) {
			return out, ErrInventory
		}
		if u.HWIDDeviceLimit != nil && (*u.HWIDDeviceLimit < 0 || *u.HWIDDeviceLimit > 1000) {
			return out, ErrInventory
		}
		endpoint, e := url.Parse(u.SubscriptionURL)
		if e != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.RawPath != "" || !strings.HasSuffix(endpoint.Path, "/"+u.ShortUUID) {
			return out, ErrInventory
		}
		base := strings.TrimSuffix(endpoint.String(), u.ShortUUID)
		if out.SubscriptionBase != "" && out.SubscriptionBase != base {
			return out, ErrInventory
		}
		out.SubscriptionBase = base
		m.Username = u.Username
		m.ShortUUID = u.ShortUUID
		m.HWIDDeviceLimit = u.HWIDDeviceLimit
		m.CreatedAt = u.CreatedAt
		m.LifetimeBytes = *u.Traffic.Lifetime
		m.SquadIDs = []string{}
		if m.CreatedAt.IsZero() {
			return out, ErrInventory
		}
		seen := map[string]bool{}
		for _, entry := range u.InternalSquads {
			var s Squad
			if json.Unmarshal(entry, &s) != nil {
				return out, ErrInventory
			}
			s.UUID = strings.ToLower(s.UUID)
			if !knownSquads[s.UUID] || seen[s.UUID] {
				return out, ErrInventory
			}
			seen[s.UUID] = true
			m.SquadIDs = append(m.SquadIDs, s.UUID)
		}
		sort.Strings(m.SquadIDs)
		out.Users = append(out.Users, m)
		knownUsers[m.ID] = true
	}
	seenDevices := map[int64]map[string]bool{}
	for _, entry := range source.Devices {
		var d Device
		// Source history can predate creation after earlier imports. Require both
		// timestamps, but preserve their original ordering instead of rewriting it.
		if json.Unmarshal(entry, &d) != nil || !knownUsers[d.UserID] || len(d.HWID) == 0 || !bounded(&d.HWID, 512) || !bounded(d.Platform, 2048) || !bounded(d.OSVersion, 2048) || !bounded(d.Model, 2048) || d.CreatedAt.IsZero() || d.UpdatedAt.IsZero() {
			return out, ErrInventory
		}
		if seenDevices[d.UserID] == nil {
			seenDevices[d.UserID] = map[string]bool{}
		}
		if seenDevices[d.UserID][d.HWID] {
			return out, ErrInventory
		}
		seenDevices[d.UserID][d.HWID] = true
		out.Devices = append(out.Devices, d)
	}
	out.SHA256 = report.SHA256
	out.CapturedAt = source.CapturedAt
	sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].ID < out.Users[j].ID })
	sort.Slice(out.Squads, func(i, j int) bool { return out.Squads[i].UUID < out.Squads[j].UUID })
	sort.Slice(out.Devices, func(i, j int) bool {
		a, b := out.Devices[i], out.Devices[j]
		if a.UserID == b.UserID {
			return a.HWID < b.HWID
		}
		return a.UserID < b.UserID
	})
	return out, nil
}
