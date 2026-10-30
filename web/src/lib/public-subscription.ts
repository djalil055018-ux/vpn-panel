export type PublicSubscription = {
  name: string; brand: string; support_url: string; support_label: string;
  status: "active" | "expired" | "disabled" | "quota_exceeded";
  expires_at: string | null; used_bytes: number; limit_bytes: number;
  reset_policy: string; device_limit: number; device_count: number; updated_at: string;
  auto_profile?: { name: string; russia_direct: boolean };
};
export function publicSupportURL(value: string): string | null {
  try { const url = new URL(value); return url.protocol === "https:" && !url.username && !url.password ? url.href : null; } catch { return null; }
}
export function trafficLabel(value: number): string {
  if (value <= 0) return "0 Б";
  const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ"];
  const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return new Intl.NumberFormat("ru", { maximumFractionDigits: unit > 0 ? 1 : 0 }).format(value / 1024 ** unit) + " " + units[unit];
}
