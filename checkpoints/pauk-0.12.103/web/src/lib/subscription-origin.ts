function webOrigin(value: string | undefined): string {
  if (!value?.trim()) throw new Error("Public origin is not configured");
  const url = new URL(value.trim());
  const localHTTP = url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if ((url.protocol !== "https:" && !localHTTP) || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("Public origin must be an HTTPS origin");
  }
  return url.origin;
}

export function subscriptionOrigin(dedicated: string | undefined, panel: string | undefined): string {
  return webOrigin(dedicated?.trim() || panel);
}

export function subscriptionURL(path: string, dedicated: string | undefined, panel: string | undefined): string {
  if (!/^\/sub\/[A-Za-z0-9_-]{16,128}$/.test(path)) throw new Error("Invalid subscription path");
  return new URL(path, subscriptionOrigin(dedicated, panel)).href;
}

export function customerRequestOriginAllowed(origin: string | null, panel: string | undefined, dedicated: string | undefined): boolean {
  if (!origin) return false;
  try {
    return [webOrigin(panel), subscriptionOrigin(dedicated, panel)].includes(origin);
  } catch {
    return false;
  }
}
