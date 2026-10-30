import "server-only";
import { createHmac, timingSafeEqual } from "crypto";
import { cache } from "react";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import type { AdminAccount, AdminSession, AdminRole } from "@/lib/admin-types";

const COOKIE_NAME = "vpn_platform_session";
const TTL = 8 * 60 * 60;
const SESSION_PATTERN = /^vpa1_[A-Za-z0-9_-]{43}$/;
const BASE_URL = process.env.CONTROL_PLANE_URL ?? "http://127.0.0.1:8080";
export type WebSession = { user: string; role: AdminRole; accountID: string; sessionID: string | null; exp: number; legacy: boolean };
type Authentication = { session: WebSession; credential: string };

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

// Credentials and API error bodies never leave this server-only module.
async function authRequest<T>(path: string, credential: string, body?: unknown): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { Authorization: `Bearer ${credential}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store", signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error("Authentication unavailable or credential rejected");
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

async function bootstrapOwner() {
  return authRequest<{ initialized: boolean; owner: AdminAccount | null }>(
    "/api/v1/admin/bootstrap", requiredEnv("CONTROL_PLANE_ADMIN_TOKEN"),
    { username: requiredEnv("WEB_ADMIN_USER"), password_hash: requiredEnv("WEB_ADMIN_PASSWORD_HASH") },
  );
}

function webSession(session: AdminSession): WebSession {
  return { user: session.account.username, role: session.account.role, accountID: session.account.id, sessionID: session.id, exp: Date.parse(session.expires_at) / 1000, legacy: false };
}

export async function loginAdmin(username: string, password: string, factor = ""): Promise<WebSession | null> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(username) || !password || Buffer.byteLength(password) > 1024 || factor.length > 64) return null;
  try {
    await bootstrapOwner();
    const result = await authRequest<{ session_token: string; session: AdminSession }>(
      "/api/v1/admin/login", requiredEnv("CONTROL_PLANE_ADMIN_TOKEN"), { username, password, code: /^\d{6}$/.test(factor) ? factor : "", recovery_code: factor && !/^\d{6}$/.test(factor) ? factor : "" },
    );
    if (!SESSION_PATTERN.test(result.session_token)) return null;
    const session = webSession(result.session);
    const store = await cookies();
    store.set(COOKIE_NAME, result.session_token, {
      httpOnly: true, secure: true, sameSite: "strict", path: "/",
      expires: new Date(session.exp * 1000), maxAge: Math.max(0, Math.min(TTL, Math.floor(session.exp - Date.now() / 1000))),
    });
    return session;
  } catch { return null; }
}

const authenticateToken = cache(async (token: string | undefined): Promise<Authentication | null> => {
  if (!token || token.length > 2048) return null;
  try {
    if (SESSION_PATTERN.test(token)) {
      const session = await authRequest<AdminSession>("/api/v1/admin/me", token);
      return { session: webSession(session), credential: token };
    }
    // A bounded transition for existing signed cookies. Never accept a failed
    // personal token as a legacy cookie or refresh a legacy session's expiry.
    const parts = token.split(".");
    if (parts.length !== 2) return null;
    const [body, signature] = parts;
    const expected = createHmac("sha256", requiredEnv("WEB_SESSION_SECRET")).update(body).digest("base64url");
    if (signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    const now = Math.floor(Date.now() / 1000);
    if (payload.user !== requiredEnv("WEB_ADMIN_USER") || !Number.isSafeInteger(payload.exp) || payload.exp <= now || payload.exp > now + TTL) return null;
    const { owner } = await bootstrapOwner();
    if (!owner || !owner.enabled || owner.role !== "owner" || owner.security_version !== 1 || owner.username !== payload.user) return null;
    const bridgeEnds = Math.floor(Date.parse(owner.created_at) / 1000) + TTL;
    if (!Number.isFinite(bridgeEnds) || now >= bridgeEnds || payload.exp > bridgeEnds) return null;
    return { session: { user: owner.username, accountID: owner.id, sessionID: null, role: "owner", exp: payload.exp, legacy: true }, credential: requiredEnv("CONTROL_PLANE_ADMIN_TOKEN") };
  } catch { return null; }
});

async function readAuthentication(): Promise<Authentication | null> {
  return authenticateToken((await cookies()).get(COOKIE_NAME)?.value);
}

// A fresh password+factor proof minted this replacement in the same database
// transaction that revoked prior sessions. Credentials stay server-only.
export async function replacePersonalSession(token: string, value: AdminSession) {
  if (!SESSION_PATTERN.test(token)) throw new Error("Invalid personal session");
  const session = webSession(value), store = await cookies();
  store.set(COOKIE_NAME, token, { httpOnly: true, secure: true, sameSite: "strict", path: "/", expires: new Date(session.exp * 1000), maxAge: Math.max(0, Math.min(TTL, Math.floor(session.exp - Date.now() / 1000))) });
}

export async function getSession(): Promise<WebSession | null> {
  return (await readAuthentication())?.session ?? null;
}
export async function requireSession(): Promise<WebSession> {
  const session = await getSession();
  if (!session) redirect("/login");
  return session;
}
export async function adminAuthorization(): Promise<string> {
  const auth = await readAuthentication();
  if (!auth) redirect("/login");
  return auth.credential;
}
export async function destroySession() {
  const store = await cookies();
  const token = store.get(COOKIE_NAME)?.value;
  try {
    if (token && SESSION_PATTERN.test(token)) await authRequest("/api/v1/admin/logout", token, {});
  } catch { /* Local logout must remain possible during a Control Plane outage. */ }
  store.delete(COOKIE_NAME);
}
