export type TrafficQuotaUsage = {
  monthly_limit_bytes: number;
  traffic_limit_bytes?: number;
  reset_policy?: "MONTH" | "NO_RESET";
  imported_bytes?: number;
};

export function trafficQuota(usage: TrafficQuotaUsage) {
  const policy = usage.reset_policy ?? "MONTH";
  if (policy !== "MONTH" && policy !== "NO_RESET") return null;
  const limit = policy === "NO_RESET" ? usage.traffic_limit_bytes : usage.monthly_limit_bytes;
  if (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit < 0) return null;
  return { limit, continuous: policy === "NO_RESET" };
}
