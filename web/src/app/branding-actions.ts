"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { saveTenantBranding } from "@/lib/control-plane";
import { portalFetch, portalIdentity } from "@/lib/portal-api";
import { brandingInput } from "@/lib/branding-values";
export type BrandingState = { ok: boolean; message: string };
export async function adminBrandingAction(_prior: BrandingState, form: FormData): Promise<BrandingState> {
  await requireSession();const tenant = String(form.get("tenant_id") ?? ""), input = brandingInput(form);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenant) || !input) return { ok: false, message: "Проверьте название, цвет и HTTPS-ссылку поддержки с подписью." };
  try { await saveTenantBranding(tenant, input);revalidatePath("/branding");revalidatePath("/portal");return { ok: true, message: "Оформление сохранено. Оно видно после входа в кабинет владельца." }; } catch { return { ok: false, message: "Не удалось сохранить оформление. Повторите позже." }; }
}
export async function portalBrandingAction(_prior: BrandingState, form: FormData): Promise<BrandingState> {
  const input = brandingInput(form);if (!input) return { ok: false, message: "Проверьте название, цвет и HTTPS-ссылку поддержки с подписью." };
  try { if ((await portalIdentity()).role !== "operator") return { ok: false, message: "Этот ключ разрешает только просмотр." };await portalFetch("/branding", "PUT", input);revalidatePath("/portal");revalidatePath("/branding");return { ok: true, message: "Оформление кабинета сохранено." }; } catch { return { ok: false, message: "Не удалось сохранить оформление. Проверьте сеанс и повторите позже." }; }
}
