package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
	"vpn-platform/internal/model"
)

var backupIDPattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)

func validBackupReport(v model.BackupStatus, now time.Time) bool {
	if v.Status != "verified" && v.Status != "failed" {
		return false
	}
	if v.SizeBytes < 0 || v.FreeBytes < 0 || v.ReportedAt != nil {
		return false
	}
	if v.Verification != "" && v.Verification != "archive_integrity" {
		return false
	}
	if v.ID != "" && !backupIDPattern.MatchString(v.ID) {
		return false
	}
	if v.LastSuccessAt != nil && v.LastSuccessAt.After(now.Add(5*time.Minute)) {
		return false
	}
	if v.LastVerifiedAt != nil && v.LastVerifiedAt.After(now.Add(5*time.Minute)) {
		return false
	}
	if v.Status == "verified" && (v.ID == "" || v.LastSuccessAt == nil || v.LastVerifiedAt == nil || v.Verification != "archive_integrity") {
		return false
	}
	return true
}
func (a *application) agentBackupStatus(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	var input model.BackupStatus
	if err := d.Decode(&input); err != nil || !validBackupReport(input, time.Now().UTC()) {
		writeError(w, 400, "invalid backup report")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		writeError(w, 400, "one JSON object required")
		return
	}
	node := currentNode(r.Context())
	if err := a.store.SaveNodeBackupReport(r.Context(), node.ID, input); err != nil {
		writeError(w, 500, "backup report unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *application) getOperationsStatus(w http.ResponseWriter, r *http.Request) {
	out, err := a.store.OperationsStatus(r.Context())
	if err != nil {
		writeError(w, 503, "operations status temporarily unavailable")
		return
	}
	if f, err := os.Open("/var/lib/vpn-platform/operations/control-plane-backup.json"); err == nil {
		defer f.Close()
		var backup model.BackupStatus
		if json.NewDecoder(io.LimitReader(f, 65536)).Decode(&backup) == nil {
			out.ControlPlaneBackup = &backup
		}
	}
	out.ControlPlaneFreeBytes = operationsFreeBytes()
	if f, err := os.Open("/var/lib/vpn-platform/operations/restore-drill.json"); err == nil {
		defer f.Close()
		out.RestoreDrill = decodeRestoreDrill(f, time.Now().UTC())
	}
	writeJSON(w, 200, out)
}

var drillVersionPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

func decodeRestoreDrill(reader io.Reader, now time.Time) *model.RestoreDrillStatus {
	var v model.RestoreDrillStatus
	if json.NewDecoder(io.LimitReader(reader, 4096)).Decode(&v) != nil {
		return nil
	}
	if v.Status == "failed" {
		if v.CheckedAt == nil || v.CheckedAt.After(now.Add(5*time.Minute)) {
			return nil
		}
		return &model.RestoreDrillStatus{Status: "failed", CheckedAt: v.CheckedAt}
	}
	if v.Status != "verified" || !backupIDPattern.MatchString(v.BackupID) || v.VerifiedAt == nil || v.VerifiedAt.After(now.Add(5*time.Minute)) || !drillVersionPattern.MatchString(v.ControlPlaneVersion) || v.Verification != "database_and_application_boot" || v.WebPages < 1 || v.WebPages > 100 || v.DurationSeconds < 0 || v.DurationSeconds > 3600 {
		return nil
	}
	return &v
}
