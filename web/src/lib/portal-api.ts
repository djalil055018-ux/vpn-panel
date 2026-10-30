import "server-only";
import { cookies } from "next/headers";
import { sealPortalSession, openPortalSession } from "@/lib/portal-session-crypto";

const cookieName = "vpn_tenant_portal";
export type PortalIdentity = { tenant_id: string; credential_id: string; role: "viewer" | "operator" | "reseller"; expires_at: string };
export type PortalClient = { id: string; name: string; status: string; effective_status: string; expires_at: string | null; remnawave_hold?: boolean };
export type PortalClientUsage = { client_id: string; used_bytes: number; monthly_limit_bytes: number; traffic_limit_bytes?: number; reset_policy?: "MONTH" | "NO_RESET"; imported_bytes?: number; remaining_bytes: number; quota_exceeded: boolean; active_ips: number | null; device_limit: number; device_warning: boolean; last_observed_at?: string | null };
export type PortalPlan = { id: string; name: string; code: string; enabled: boolean; service_ids: string[]; client_ids: string[]; bot_client_ids?: string[] };
export type PortalService = { id: string; name: string; protocol: string; enabled: boolean };
export class PortalError extends Error { constructor(public status: number) { super("Portal request failed"); } }
function secret() { return process.env.WEB_SESSION_SECRET ?? ""; }
async function requestWithCredential<T>(credential: string, path: string, method = "GET", body?: unknown, idempotencyKey?: string): Promise<T> {
  if (!/^vpt1_[A-Za-z0-9_-]{43}$/.test(credential)) throw new PortalError(401);
  if (!/^\/[a-zA-Z0-9_/-]*$/.test(path) || path.includes("//")) throw new PortalError(400);
  const base = (process.env.CONTROL_PLANE_URL ?? "http://127.0.0.1:8080").replace(/\/$/, "");
  const response = await fetch(base + "/api/v1/tenant" + path, { method, headers: { Authorization: "Bearer " + credential, "Content-Type": "application/json", ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}) }, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", redirect: "error", signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new PortalError(response.status);
  return response.status === 204 ? undefined as T : await response.json() as T;
}
export function authenticatePortalCredential(credential: string) { return requestWithCredential<PortalIdentity>(credential, "/me"); }
export async function setPortalSession(credential: string, expires: string) {
  const now = Date.now(), expiry = Math.min(now + 8 * 3600000, Date.parse(expires));
  if (!Number.isFinite(expiry) || expiry <= now) throw new PortalError(401);
  (await cookies()).set(cookieName, sealPortalSession(credential, expiry, secret()), { httpOnly: true, secure: true, sameSite: "strict", path: "/portal", maxAge: Math.floor((expiry - now) / 1000) });
}
export async function clearPortalSession() { (await cookies()).set(cookieName, "", { httpOnly: true, secure: true, sameSite: "strict", path: "/portal", maxAge: 0 }); }
export async function portalFetch<T>(path: string, method = "GET", body?: unknown, idempotencyKey?: string): Promise<T> {
  const value = (await cookies()).get(cookieName)?.value;
  const credential = value ? openPortalSession(value, secret()) : null;
  if (!credential) throw new PortalError(401);
  return requestWithCredential<T>(credential, path, method, body, idempotencyKey);
}
export function portalIdentity() { return portalFetch<PortalIdentity>("/me"); }
