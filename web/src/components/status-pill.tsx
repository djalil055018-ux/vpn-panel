import {
  STATUS_LABELS,
} from "@/lib/i18n/status";

export function StatusPill({
  value,
}: {
  value: string;
}) {
  const normalized =
    value
      .trim()
      .toLowerCase();

  let tone = "neutral";

  if (
    normalized === "online" ||
    normalized === "healthy" ||
    normalized === "ok" ||
    normalized === "completed" ||
    normalized === "stable" ||
    normalized === "approved"
  ) {
    tone = "success";
  } else if (
    normalized === "degraded" ||
    normalized === "warning" ||
    normalized === "updating" ||
    normalized === "recovering" ||
    normalized === "pending" ||
    normalized === "provisioning" ||
    normalized === "applying" ||
    normalized === "testing" ||
    normalized === "canary" ||
    normalized === "pinned"
  ) {
    tone = "warning";
  } else if (
    normalized === "offline" ||
    normalized === "failed" ||
    normalized === "error" ||
    normalized === "rolled_back" ||
    normalized === "revoked" ||
    normalized === "blocked" ||
    normalized === "cancelled" ||
    normalized === "canceled"
  ) {
    tone = "danger";
  }

  return (
    <span
      className={`status ${tone}`}
    >
      <span className="status-dot" />
      {STATUS_LABELS[normalized] ?? value}
    </span>
  );
}
