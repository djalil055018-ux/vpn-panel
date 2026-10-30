export type TenantBranding = { tenant_id: string; display_name: string; tagline: string; support_label: string; support_url: string; accent: string };
export const brandAccents = [{ value: "blue", label: "Синий", color: "#88b4ff" }, { value: "violet", label: "Фиолетовый", color: "#c2a5ff" }, { value: "teal", label: "Бирюзовый", color: "#70dccc" }, { value: "amber", label: "Янтарный", color: "#f5ca78" }, { value: "rose", label: "Розовый", color: "#f6a3c3" }];
export function brandingInput(form: FormData): Omit<TenantBranding, "tenant_id"> | null {
  const get = (key: string) => String(form.get(key) ?? "").trim();
  const value = { display_name: get("display_name"), tagline: get("tagline"), support_label: get("support_label"), support_url: get("support_url"), accent: get("accent") };
  if (!value.display_name || [...value.display_name].length > 80 || [...value.tagline].length > 160 || [...value.support_label].length > 40 || [...value.support_url].length > 500 || Object.values(value).some(text => /[\u0000-\u001f\u007f-\u009f]/.test(text)) || !brandAccents.some(accent => accent.value === value.accent) || Boolean(value.support_url) !== Boolean(value.support_label)) return null;
  if (value.support_url) { try { const url = new URL(value.support_url); if (url.protocol !== "https:" || !url.hostname || url.username || url.password || /[\\\s]/.test(value.support_url)) return null; } catch { return null; } }
  return value;
}
