export const GIB = 1073741824;
export const MAX_MONTHLY_BYTES = 9000000000000000;

// A power-of-two conversion preserves integer byte limits exactly, including
// limits originally set through the API rather than this form.
export function monthlyBytesFromGiB(raw: string): number | null {
  const value = raw.trim();
  if (!/^(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(value)) return null;
  const bytes = Number(value) * GIB;
  return Number.isSafeInteger(bytes) && bytes >= 0 && bytes <= MAX_MONTHLY_BYTES ? bytes : null;
}
