"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { acknowledgeIncident } from "@/lib/control-plane";
export type IncidentActionState = { ok: boolean; message: string };
export async function acknowledgeIncidentAction(_prior: IncidentActionState, form: FormData): Promise<IncidentActionState> {
  await requireSession();const id = String(form.get("id") ?? "");if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return { ok: false, message: "Некорректный инцидент." };
  try { await acknowledgeIncident(id);revalidatePath("/incidents");return { ok: true, message: "Отмечено. Инцидент закроется после восстановления." }; } catch { return { ok: false, message: "Не удалось отметить инцидент. Возможно, он уже закрыт; обновите страницу." }; }
}
