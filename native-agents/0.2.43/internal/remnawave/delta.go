package remnawave

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

var ErrDeltaSource = errors.New("comparison requires a later inventory from the same Remnawave source")

// DeltaReport contains counts only. No user identity, credentials, devices or
// configuration values are returned, even when an unknown source field changes.
type DeltaReport struct {
	BeforeSHA256       string         `json:"before_sha256"`
	AfterSHA256        string         `json:"after_sha256"`
	BeforeCapturedAt   time.Time      `json:"before_captured_at"`
	AfterCapturedAt    time.Time      `json:"after_captured_at"`
	BeforeUsers        int            `json:"before_users"`
	AfterUsers         int            `json:"after_users"`
	AddedUsers         int            `json:"added_users"`
	RemovedUsers       int            `json:"removed_users"`
	ChangedUsers       int            `json:"changed_users"`
	UnchangedUsers     int            `json:"unchanged_users"`
	ChangedCategories  map[string]int `json:"changed_user_categories"`
	ChangedCollections []string       `json:"changed_collections"`
	IdenticalBytes     bool           `json:"identical_bytes"`
	ReviewRequired     bool           `json:"review_required"`
	CutoverReady       bool           `json:"cutover_ready"`
}

// Decode numbers as exact decimal JSON tokens; int64 usage must never pass
// through float64, and unknown fields must participate in the comparison.
func deltaObject(raw []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value map[string]any
	err := d.Decode(&value)
	return value, err
}

func Compare(before, after []byte) (DeltaReport, error) {
	var out DeltaReport
	old, oldReport, err := Parse(before)
	if err != nil {
		return out, err
	}
	next, nextReport, err := Parse(after)
	if err != nil {
		return out, err
	}
	if old.SourceOrigin != next.SourceOrigin || next.CapturedAt.Before(old.CapturedAt) {
		return out, ErrDeltaSource
	}
	oldRaw, err := deltaObject(before)
	if err != nil {
		return out, ErrInventory
	}
	nextRaw, err := deltaObject(after)
	if err != nil {
		return out, ErrInventory
	}
	out = DeltaReport{BeforeSHA256: oldReport.SHA256, AfterSHA256: nextReport.SHA256, BeforeCapturedAt: old.CapturedAt, AfterCapturedAt: next.CapturedAt, BeforeUsers: len(old.Users), AfterUsers: len(next.Users), ChangedCategories: map[string]int{}, ChangedCollections: []string{}, IdenticalBytes: bytes.Equal(before, after)}
	previous := map[json.Number]map[string]any{}
	for _, row := range oldRaw["users"].([]any) {
		u := row.(map[string]any)
		previous[u["id"].(json.Number)] = u
	}
	groups := map[string][]string{
		"identity_credentials": {"uuid", "shortUuid", "vlessUuid", "trojanPassword", "ssPassword", "subscriptionUrl"},
		"name":                 {"username"}, "status": {"status"}, "expiry": {"expireAt"},
		"traffic_limit": {"trafficLimitBytes", "trafficLimitStrategy"},
		"traffic_usage": {"userTraffic"}, "hwid_limit": {"hwidDeviceLimit"},
		"squads": {"activeInternalSquads", "externalSquadUuid"},
	}
	known := map[string]bool{"id": true}
	for _, fields := range groups {
		for _, key := range fields {
			known[key] = true
		}
	}
	for _, row := range nextRaw["users"].([]any) {
		current := row.(map[string]any)
		id := current["id"].(json.Number)
		prior, exists := previous[id]
		if !exists {
			out.AddedUsers++
			continue
		}
		delete(previous, id)
		if reflect.DeepEqual(prior, current) {
			out.UnchangedUsers++
			continue
		}
		out.ChangedUsers++
		for group, fields := range groups {
			for _, key := range fields {
				a, aExists := prior[key]
				b, bExists := current[key]
				if aExists != bExists || !reflect.DeepEqual(a, b) {
					out.ChangedCategories[group]++
					break
				}
			}
		}
		oldExtra := map[string]any{}
		newExtra := map[string]any{}
		for key, value := range prior {
			if !known[key] {
				oldExtra[key] = value
			}
		}
		for key, value := range current {
			if !known[key] {
				newExtra[key] = value
			}
		}
		if !reflect.DeepEqual(oldExtra, newExtra) {
			out.ChangedCategories["other_source_fields"]++
		}
	}
	out.RemovedUsers = len(previous)
	for _, key := range []string{"devices", "internal_squads", "external_squads", "hosts", "nodes", "config_profiles", "source_metadata"} {
		if !reflect.DeepEqual(oldRaw[key], nextRaw[key]) {
			out.ChangedCollections = append(out.ChangedCollections, key)
		}
	}
	// Inventory envelope changes outside the known export metadata are also
	// reviewable, so future exporter fields can never vanish silently.
	envelope := map[string]bool{"users": true, "devices": true, "internal_squads": true, "external_squads": true, "hosts": true, "nodes": true, "config_profiles": true, "source_metadata": true, "started_at": true, "captured_at": true, "verification": true}
	a := map[string]any{}
	b := map[string]any{}
	for key, value := range oldRaw {
		if !envelope[key] {
			a[key] = value
		}
	}
	for key, value := range nextRaw {
		if !envelope[key] {
			b[key] = value
		}
	}
	if !reflect.DeepEqual(a, b) {
		out.ChangedCollections = append(out.ChangedCollections, "other_inventory_fields")
	}
	out.ReviewRequired = out.AddedUsers > 0 || out.RemovedUsers > 0 || out.ChangedUsers > 0 || len(out.ChangedCollections) > 0
	return out, nil
}
