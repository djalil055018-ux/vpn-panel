/** A public URL is deployment configuration, never a request Host header. */
export function installationOrigin(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") return null;
    if (!/^[a-z0-9.-]+$/.test(url.hostname) || url.hostname.split(".").some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
    return url.origin;
  } catch {
    return null;
  }
}
