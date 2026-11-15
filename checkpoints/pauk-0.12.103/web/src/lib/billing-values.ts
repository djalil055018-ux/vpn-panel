export type BillingOffer = { id: string; tenant_id: string; plan_id: string; name: string; amount_minor: number; currency: string; duration_days: number; enabled: boolean };
export type BillingInvoice = { id: string; tenant_id: string; offer_id: string; client_id: string; client_deleted?: boolean; plan_id: string; offer_name: string; amount_minor: number; currency: string; duration_days: number; status: "pending" | "paid" | "void"; paid_at: string | null; entitlement_expires_at: string | null; created_at: string; payment_reference: string | null; payment_source: string | null };
export const billingCurrencies = ["RUB", "USD", "EUR", "PLN", "SEK"];
export function parseMinorUnits(text: string): number | null {
  const normalized = text.trim().replace(",", ".");
  if (!/^\d{1,11}(\.\d{1,2})?$/.test(normalized)) return null;
  const [whole, fraction = ""] = normalized.split(".");
  const value = BigInt(whole) * BigInt(100) + BigInt(fraction.padEnd(2, "0"));
  return value >= BigInt(1) && value <= BigInt(1000000000000) ? Number(value) : null;
}
export function billingMoney(amount: number, currency: string) { return new Intl.NumberFormat("ru-RU", { style: "currency", currency }).format(amount / 100); }
export function billingWhen(value: string | null) { return value ? new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Moscow" }).format(new Date(value)) : "—"; }
