"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, createTenantAPICredential, getTenantAPICredentials, revokeTenantAPICredential } from "@/lib/control-plane";

export type CredentialActionState = { ok: boolean; message: string; token?: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export async function tenantCredentialAction(_previous: CredentialActionState, form: FormData): Promise<CredentialActionState> {
  await requireSession();
  const field = (name: string) => String(form.get(name) ?? "").trim();
  const tenant = field("tenant_id"), operation = field("operation");
  if (!uuid.test(tenant)) return { ok: false, message: "Выберите владельца." };
  try {
    if (operation === "create") {
      const name = field("name"), role = field("role"), days = Number(field("days"));
      if (!name || new TextEncoder().encode(name).length > 100 || !["viewer", "operator", "reseller"].includes(role) || ![7, 30, 90, 365].includes(days)) return { ok: false, message: "Проверьте название, роль и срок действия." };
      const result = await createTenantAPICredential(tenant, { name, role, expires_at: new Date(Date.now() + days * 86400000).toISOString() });
      revalidatePath("/api-access");
      return { ok: true, message: "Ключ создан. Сохраните его сейчас: повторно получить значение нельзя.", token: result.token };
    }
    const id = field("credential_id");
    if (operation !== "revoke" || !uuid.test(id) || field("confirm") !== "yes") return { ok: false, message: "Подтвердите отзыв ключа." };
    if (!(await getTenantAPICredentials(tenant)).some(token => token.id === id)) return { ok: false, message: "Ключ недоступен для выбранного владельца." };
    await revokeTenantAPICredential(id); revalidatePath("/api-access");
    return { ok: true, message: "Ключ отозван. Новые запросы с ним отклоняются." };
  } catch (error) {
    return { ok: false, message: error instanceof ControlPlaneError && error.status === 409 ? "Достигнут лимит 20 ключей или выбран вложенный владелец для партнёрской роли." : "Не удалось выполнить операцию. Обновите страницу и повторите попытку." };
  }
}
