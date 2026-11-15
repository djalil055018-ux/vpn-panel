export type ReserveSubscriptionLink = { url: string; expires_at: string };

export function reserveSubscriptionLink(
  path: string,
  origin: string | undefined,
  expires: string | undefined,
  now = Date.now(),
): ReserveSubscriptionLink | null {
  if (!origin || !expires || !/^\/sub\/[A-Za-z0-9_-]{16,128}$/.test(path)) return null;
  const expiresAt = Date.parse(expires);
  if (!Number.isFinite(expiresAt) || expiresAt <= now) return null;
  try {
    const base = new URL(origin);
    if (base.protocol !== "https:" || base.username || base.password || base.pathname !== "/" || base.search || base.hash) return null;
    return { url: new URL(path, base).href, expires_at: new Date(expiresAt).toISOString() };
  } catch {
    return null;
  }
}
