export const localRealityTarget = "127.0.0.1:18443";

export function ownCoverDomain(value: string): boolean {
  const reserved = [process.env.VPN_PLATFORM_PUBLIC_URL, process.env.VPN_PLATFORM_SUBSCRIPTION_URL]
    .flatMap(origin => {
      if (!origin) return [];
      try { return [new URL(origin).hostname]; } catch { return []; }
    });
  return value.length <= 253 && !reserved.includes(value)
    && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(value);
}

export function globallyRoutableIPv4(address: string): boolean {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) return false;
  const [a, b, c, d] = address.split(".").map(Number);
  if ([a, b, c, d].some(part => part > 255)) return false;
  return a > 0 && a < 224 && a !== 10 && a !== 127
    && !(a === 100 && b >= 64 && b <= 127)
    && !(a === 169 && b === 254)
    && !(a === 172 && b >= 16 && b <= 31)
    && !(a === 192 && ((b === 0 && (c === 0 || c === 2)) || b === 168 || (b === 88 && c === 99)))
    && !(a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
    && !(a === 203 && b === 0 && c === 113);
}
