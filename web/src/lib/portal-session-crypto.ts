import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

const context = "vpn-platform:tenant-portal:v1";
const tokenPattern = /^vpt1_[A-Za-z0-9_-]{43}$/;
function key(secret: string) { if (secret.length < 32) throw new Error("Portal session secret is not configured"); return createHmac("sha256", secret).update(context).digest(); }
export function sealPortalSession(credential: string, expiresAt: number, secret: string): string {
  if (!tokenPattern.test(credential) || !Number.isSafeInteger(expiresAt)) throw new Error("Invalid portal session");
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key(secret), nonce);
  cipher.setAAD(Buffer.from(context));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify({ credential, exp: expiresAt }), "utf8"), cipher.final()]);
  return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]).toString("base64url");
}
export function openPortalSession(value: string, secret: string, now = Date.now()): string | null {
  try {
    if (value.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
    const raw = Buffer.from(value, "base64url"); if (raw.length < 29) return null;
    const decipher = createDecipheriv("aes-256-gcm", key(secret), raw.subarray(0, 12));
    decipher.setAAD(Buffer.from(context)); decipher.setAuthTag(raw.subarray(12, 28));
    const payload = JSON.parse(Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8"));
    if (typeof payload.credential !== "string" || !tokenPattern.test(payload.credential) || !Number.isSafeInteger(payload.exp) || payload.exp <= now) return null;
    return payload.credential;
  } catch { return null; }
}
