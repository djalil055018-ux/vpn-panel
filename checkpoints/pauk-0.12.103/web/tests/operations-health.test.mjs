import assert from "node:assert/strict";
import test from "node:test";
import { backupFreshAt, restoreEvidenceState } from "../src/lib/operations-health.ts";

const at = "2026-11-09T18:00:00Z";
const backup = { id: "20261109T173000Z-1234abcd", status: "verified", last_success_at: "2026-11-09T17:30:00Z", last_verified_at: "2026-11-09T17:31:00Z", verification: "database_restore" };
const restore = { status: "verified", backup_id: backup.id, verified_at: "2026-11-09T17:40:00Z", control_plane_version: "0.1.175" };

test("fresh saved data without valid verification never appears as a verified backup", () => {
  assert.equal(backupFreshAt(backup, at), true);
  for (const value of [
    null, { ...backup, status: "failed" }, { ...backup, verification: "unknown" },
    { ...backup, last_verified_at: null }, { ...backup, last_success_at: "invalid" },
    { ...backup, last_success_at: "2026-11-09T19:00:00Z" },
    { ...backup, last_verified_at: "2026-11-09T19:00:00Z" },
    { ...backup, last_verified_at: "2026-11-09T17:29:00Z" },
  ]) assert.equal(backupFreshAt(value, at), false);
  assert.equal(backupFreshAt(backup, "2026-11-11T05:30:00Z"), false);
  assert.equal(backupFreshAt(backup, "invalid"), false);
});

test("historical boot proof cannot confirm a new or unverified backup", () => {
  assert.equal(restoreEvidenceState(restore, backup, at, "0.1.175"), "verified_current_backup");
  for (const [proof, saved, version] of [
    [restore, { ...backup, id: "another-backup" }, "0.1.175"],
    [restore, null, "0.1.175"],
    [{ ...restore, verified_at: "2026-10-15T01:55:04Z" }, backup, "0.1.175"],
    [{ ...restore, verified_at: "2026-11-09T17:30:30Z" }, backup, "0.1.175"],
  ]) assert.equal(restoreEvidenceState(proof, saved, at, version), "verified_historical");
});

test("a verified exact copy stays identified when the live release changes or is unknown", () => {
  assert.equal(restoreEvidenceState(restore, backup, at, "0.1.176"), "verified_current_backup_other_release");
  for (const version of [null, "", "invalid"])
    assert.equal(restoreEvidenceState(restore, backup, at, version), "verified_current_backup_release_unknown");
  assert.equal(restoreEvidenceState(restore, { ...backup, id: "new-copy" }, at, null), "verified_historical");
  assert.equal(restoreEvidenceState({ ...restore, control_plane_version: "unknown" }, backup, at, "0.1.175"), "unavailable");
});

test("missing, failed and invalid restore evidence have separate states", () => {
  assert.equal(restoreEvidenceState(null, backup, at, "0.1.175"), "missing");
  assert.equal(restoreEvidenceState({ ...restore, status: "failed" }, backup, at, "0.1.175"), "failed");
  for (const verified_at of [null, "invalid", "2026-11-09T19:00:00Z"])
    assert.equal(restoreEvidenceState({ ...restore, verified_at }, backup, at, "0.1.175"), "unavailable");
});
