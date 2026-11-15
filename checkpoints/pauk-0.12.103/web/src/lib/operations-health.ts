type BackupEvidence = {
  id: string;
  status: string;
  last_success_at: string | null;
  last_verified_at: string | null;
  verification: string;
};
type RestoreEvidence = {
  status: string;
  backup_id: string;
  verified_at: string | null;
  control_plane_version: string;
};

export type NodeRestoreEvidence = {
  node_id: string;
  status: string;
  backup_id: string;
  archive_sha256: string;
  checked_at: string | null;
  verified_at: string | null;
  verification: string;
  core_type: string;
  core_version: string;
  runtime_package_source: string;
  archive_integrity_verified: boolean;
  configuration_contents_verified: boolean;
  core_config_accepted: boolean;
  core_started: boolean;
  network_isolated: boolean;
  cleanup_verified: boolean;
  expected_tcp_listeners: number;
  observed_tcp_listeners: number;
  runtime_artifacts_complete: boolean;
  full_node_disaster_recovery_tested: boolean;
};

function timestamp(value: string | null) {
  return value ? Date.parse(value) : NaN;
}

export function backupFreshAt(backup: BackupEvidence | null, at: string) {
  if (!backup || backup.status !== "verified" || !["archive_integrity", "database_restore"].includes(backup.verification)) return false;
  const now = Date.parse(at), saved = timestamp(backup.last_success_at), verified = timestamp(backup.last_verified_at);
  return [now, saved, verified].every(Number.isFinite) && saved <= verified && verified <= now && now - saved < 36 * 3600_000 && now - verified < 36 * 3600_000;
}

export function restoreEvidenceState(restore: RestoreEvidence | null, backup: BackupEvidence | null, at: string, runningVersion: string | null) {
  if (!restore) return "missing";
  if (restore.status === "failed") return "failed";
  const now = Date.parse(at), verified = timestamp(restore.verified_at);
  if (restore.status !== "verified" || !Number.isFinite(now) || !Number.isFinite(verified) || verified > now || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(restore.control_plane_version)) return "unavailable";
  const currentCopy = backup !== null && backupFreshAt(backup, at) && restore.backup_id === backup.id && verified >= timestamp(backup.last_verified_at) && now - verified < 7 * 24 * 3600_000;
  if (!currentCopy) return "verified_historical";
  if (!runningVersion || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(runningVersion)) return "verified_current_backup_release_unknown";
  return runningVersion === restore.control_plane_version ? "verified_current_backup" : "verified_current_backup_other_release";
}

export function nodeRestoreEvidenceState(restore: NodeRestoreEvidence | null, backup: BackupEvidence | null, at: string, nodeID: string) {
  if (!restore) return "missing";
  const now = Date.parse(at), checked = timestamp(restore.checked_at), verified = timestamp(restore.verified_at);
  if (restore.node_id !== nodeID || !Number.isFinite(now) || !Number.isFinite(checked) || checked > now) return "unavailable";
  if (restore.status === "failed") return restore.backup_id === backup?.id ? "failed" : "failed_historical";
  if (restore.status !== "verified" || !Number.isFinite(verified) || verified > checked ||
    restore.verification !== "configuration_boot_existing_runtime" || restore.core_type !== "xray" ||
    !/^[0-9a-f]{64}$/.test(restore.archive_sha256) || !/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(restore.core_version) ||
    restore.runtime_package_source !== "existing_pinned_installation" ||
    !restore.archive_integrity_verified || !restore.configuration_contents_verified || !restore.core_config_accepted || !restore.core_started ||
    !restore.network_isolated || !restore.cleanup_verified || restore.runtime_artifacts_complete || restore.full_node_disaster_recovery_tested ||
    !Number.isInteger(restore.expected_tcp_listeners) || restore.expected_tcp_listeners < 1 || restore.expected_tcp_listeners > 256 ||
    !Number.isInteger(restore.observed_tcp_listeners) || restore.observed_tcp_listeners < restore.expected_tcp_listeners || restore.observed_tcp_listeners > 1024) return "unavailable";
  return backupFreshAt(backup, at) && backup?.verification === "archive_integrity" && restore.backup_id === backup.id && verified >= timestamp(backup.last_verified_at) && now - verified < 7 * 24 * 3600_000
    ? "verified_current_backup"
    : "verified_historical";
}
