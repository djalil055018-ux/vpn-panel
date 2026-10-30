package main

import (
	"testing"
	"time"
	"vpn-platform/internal/model"
)

func TestBackupReportValidation(t *testing.T) {
	now := time.Now()
	good := model.BackupStatus{ID: "20260907T120000Z-1234abcd", Status: "verified", LastSuccessAt: &now, LastVerifiedAt: &now, Verification: "archive_integrity", SizeBytes: 1024}
	if !validBackupReport(good, now) {
		t.Fatal("valid report rejected")
	}
	for _, mutate := range []func(*model.BackupStatus){func(v *model.BackupStatus) { v.ID = "../../etc" }, func(v *model.BackupStatus) { v.SizeBytes = -1 }, func(v *model.BackupStatus) { v.LastVerifiedAt = nil }, func(v *model.BackupStatus) { v.Verification = "database_restore" }, func(v *model.BackupStatus) { v.ReportedAt = &now }, func(v *model.BackupStatus) { future := now.Add(time.Hour); v.LastVerifiedAt = &future }} {
		bad := good
		mutate(&bad)
		if validBackupReport(bad, now) {
			t.Fatal("invalid report accepted")
		}
	}
	if !validBackupReport(model.BackupStatus{Status: "failed"}, now) {
		t.Fatal("initial failure report rejected")
	}
}
