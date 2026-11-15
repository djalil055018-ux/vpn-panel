import assert from "node:assert/strict";
import test from "node:test";
import { nodeRestoreEvidenceState } from "../src/lib/operations-health.ts";

const node = "db35a2bb-16ae-443c-8ff9-819c9a735f53";
const at = "2026-11-10T04:00:00Z";
const backup = { id: "20261109T234133Z-89437f58", status: "verified", last_success_at: "2026-11-09T23:41:33Z", last_verified_at: "2026-11-09T23:41:34Z", verification: "archive_integrity" };
const restore = {
  node_id: node, status: "verified", backup_id: backup.id, archive_sha256: "a".repeat(64), checked_at: "2026-11-10T02:24:55Z", verified_at: "2026-11-10T02:24:54Z",
  verification: "configuration_boot_existing_runtime", core_type: "xray", core_version: "26.10.31", runtime_package_source: "existing_pinned_installation",
  archive_integrity_verified: true, configuration_contents_verified: true, core_config_accepted: true, core_started: true, network_isolated: true, cleanup_verified: true,
  expected_tcp_listeners: 4, observed_tcp_listeners: 5, runtime_artifacts_complete: false, full_node_disaster_recovery_tested: false,
};

test("a node boot proof only confirms its exact verified archive", () => {
  assert.equal(nodeRestoreEvidenceState(restore, backup, at, node), "verified_current_backup");
  for (const saved of [null, { ...backup, id: "20261110T234133Z-aabbccdd" }, { ...backup, status: "failed" }, { ...backup, last_verified_at: null }, { ...backup, verification: "database_restore" }, { ...backup, last_verified_at: "2026-11-10T03:00:00Z" }])
    assert.equal(nodeRestoreEvidenceState(restore, saved, at, node), "verified_historical");
  assert.equal(nodeRestoreEvidenceState(restore, backup, "2026-11-20T04:00:00Z", node), "verified_historical");
  assert.equal(nodeRestoreEvidenceState(restore, backup, at, "another-node"), "unavailable");
});

test("partial, overclaimed and malformed node proofs cannot appear verified", () => {
  for (const patch of [
    { status: "running" }, { verified_at: null }, { checked_at: null }, { verified_at: "invalid" }, { checked_at: "2026-11-10T05:00:00Z" }, { verified_at: "2026-11-10T02:24:56Z" },
    { archive_sha256: "unknown" }, { core_type: "wireguard" }, { core_version: "latest" }, { verification: "archive_integrity" }, { runtime_package_source: "unknown" },
    ...["archive_integrity_verified", "configuration_contents_verified", "core_config_accepted", "core_started", "network_isolated", "cleanup_verified"].map(key => ({ [key]: false })),
    { runtime_artifacts_complete: true }, { full_node_disaster_recovery_tested: true },
    { expected_tcp_listeners: 0 }, { expected_tcp_listeners: 2.5 }, { observed_tcp_listeners: 3 }, { observed_tcp_listeners: 1025 },
  ]) assert.equal(nodeRestoreEvidenceState({ ...restore, ...patch }, backup, at, node), "unavailable");
});

test("a failed historical drill cannot label a new archive as a failed restore", () => {
  const failed = { ...restore, status: "failed", verified_at: null };
  assert.equal(nodeRestoreEvidenceState(failed, backup, at, node), "failed");
  assert.equal(nodeRestoreEvidenceState(failed, { ...backup, id: "new-copy" }, at, node), "failed_historical");
  assert.equal(nodeRestoreEvidenceState(null, backup, at, node), "missing");
  assert.equal(nodeRestoreEvidenceState(restore, backup, "invalid", node), "unavailable");
});
