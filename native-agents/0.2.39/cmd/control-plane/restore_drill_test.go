package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRestoreDrillMetadataValidationAndRedaction(t *testing.T) {
	now := time.Now().UTC()
	value := map[string]any{"status": "verified", "backup_id": "20260907T120000Z-1234abcd", "verified_at": now.Format(time.RFC3339), "control_plane_version": "0.1.69", "verification": "database_and_application_boot", "web_pages": 11, "duration_seconds": 90, "secret": "must-not-appear"}
	read := func() string {
		raw, _ := json.Marshal(value)
		result := decodeRestoreDrill(strings.NewReader(string(raw)), now)
		if result == nil {
			return ""
		}
		out, _ := json.Marshal(result)
		return string(out)
	}
	if out := read(); out == "" || strings.Contains(out, "must-not-appear") {
		t.Fatal("safe verification metadata missing or leaked")
	}
	value["backup_id"] = "../../outside"
	if read() != "" {
		t.Fatal("invalid backup identity accepted")
	}
	value["backup_id"] = "20260907T120000Z-1234abcd"
	value["verified_at"] = now.Add(time.Hour).Format(time.RFC3339)
	if read() != "" {
		t.Fatal("future verification accepted")
	}
	value["status"] = "failed"
	value["checked_at"] = now.Format(time.RFC3339)
	if out := read(); out == "" || strings.Contains(out, "0.1.69") {
		t.Fatal("failed report retained unverified fields")
	}
}
