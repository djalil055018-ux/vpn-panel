"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { saveAutoProfile } from "@/lib/control-plane";
import { portalFetch, portalIdentity } from "@/lib/portal-api";
import { autoProfileInput } from "@/lib/auto-profile-values";
export type AutoProfileState = { ok: boolean; message: string };
const saved = { ok: true, message: "Сохранено. Клиентам нужно обновить подписку в приложении." };
export async function adminAutoProfileAction(_prior: AutoProfileState, form: FormData): Promise<AutoProfileState> {
  await requireSession();
  const tenant = String(form.get("tenant_id") ?? ""), input = autoProfileInput(form);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenant) || !input) return { ok: false, message: "Введите название: от 1 до 80 символов в одной строке." };
  try { await saveAutoProfile(tenant, input); revalidatePath("/auto-profile"); revalidatePath("/portal"); return saved; }
  catch { return { ok: false, message: "Не удалось сохранить настройки. Повторите позже." }; }
}
export async function portalAutoProfileAction(_prior: AutoProfileState, form: FormData): Promise<AutoProfileState> {
  const input = autoProfileInput(form);
  if (!input) return { ok: false, message: "Введите название: от 1 до 80 символов в одной строке." };
  try {
    if ((await portalIdentity()).role !== "operator") return { ok: false, message: "Этот ключ разрешает только просмотр." };
    await portalFetch("/auto-profile", "PUT", input); revalidatePath("/portal"); return saved;
  } catch { return { ok: false, message: "Не удалось сохранить настройки. Проверьте сеанс и повторите позже." }; }
}
