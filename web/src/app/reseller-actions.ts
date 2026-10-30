"use server";
import { revalidatePath } from "next/cache";
import { portalFetch, portalIdentity } from "@/lib/portal-api";
import { requireSession } from "@/lib/auth";
import { createPartnerOwner } from "@/lib/control-plane";
export type ResellerState = { ok: boolean; message: string; token?: string; tenantID?: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export async function createPartnerOwnerAction(_prior: ResellerState, form: FormData): Promise<ResellerState> {
  await requireSession();const name = String(form.get("name") ?? "").trim();if (!name || new TextEncoder().encode(name).length > 100) return { ok: false, message: "Укажите короткое название владельца." };
  try { const owner = await createPartnerOwner(name);revalidatePath("/partners");revalidatePath("/api-access");return { ok: true, message: "Владелец создан. Выдайте ему ключ с ролью «Партнёр».", tenantID: owner.id }; } catch { return { ok: false, message: "Не удалось создать владельца. Повторите позже." }; }
}
export async function resellerAction(_prior: ResellerState, form: FormData): Promise<ResellerState> {
  const field = (key: string) => String(form.get(key) ?? "").trim();const operation = field("operation"), child = field("child_id");
  try {
    const identity = await portalIdentity();if (identity.role !== "reseller") return { ok: false, message: "Нужен ключ с ролью «Партнёр»." };
    if (operation === "create-child") { const name = field("name");if (!name || new TextEncoder().encode(name).length > 100) return { ok: false, message: "Укажите короткое название владельца." };await portalFetch("/children", "POST", { name }); }
    else if (operation === "create-key") { const name = field("name"), role = field("role"), days = Number(field("days"));if (!uuid.test(child) || !name || new TextEncoder().encode(name).length > 100 || !["viewer", "operator"].includes(role) || ![1, 7, 30, 90].includes(days)) return { ok: false, message: "Проверьте название, роль и срок ключа." };const expiry = Math.min(Date.now() + days * 86400000, Date.parse(identity.expires_at));if (expiry < Date.now() + 3660000) return { ok: false, message: "Срок партнёрского ключа скоро заканчивается. Сначала обновите его у администратора." };const result = await portalFetch<{ token: string }>(`/children/${child}/api-tokens`, "POST", { name, role, expires_at: new Date(expiry).toISOString() });revalidatePath("/portal");return { ok: true, message: "Ключ вложенного владельца создан. Сохраните сейчас; срок ограничен вашим партнёрским ключом.", token: result.token }; }
    else if (operation === "revoke-key") { const id = field("token_id");if (!uuid.test(child) || !uuid.test(id) || field("confirm") !== "yes") return { ok: false, message: "Подтвердите отзыв ключа." };await portalFetch(`/children/${child}/api-tokens/${id}/revoke`, "POST", {}); }
    else return { ok: false, message: "Неизвестная операция." };
    revalidatePath("/portal");revalidatePath("/partners");return { ok: true, message: operation === "create-child" ? "Владелец создан. Ноды и сервисы ему назначает администратор." : "Ключ отозван." };
  } catch { return { ok: false, message: "Операция недоступна. Проверьте права, срок ключа и лимит владельцев или ключей." }; }
}
