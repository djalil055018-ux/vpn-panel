"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { saveTenantLimits, ControlPlaneError } from "@/lib/control-plane";
export async function tenantLimitAction(_previous: { ok: boolean; message: string }, form: FormData) {
  await requireSession();const tenant = String(form.get("tenant_id") ?? ""), rawClients = String(form.get("max_clients") ?? ""), rawPlans = String(form.get("max_plans") ?? ""), clients = Number(rawClients), plans = Number(rawPlans);
  if (!/^[0-9a-f-]{36}$/i.test(tenant) || !/^\d+$/.test(rawClients) || !/^\d+$/.test(rawPlans) || !Number.isInteger(clients) || clients > 100000 || !Number.isInteger(plans) || plans > 10000) return { ok: false, message: "Укажите целые лимиты: до 100000 клиентов и 10000 тарифов. Ноль снимает ограничение." };
  try { await saveTenantLimits(tenant, clients, plans);revalidatePath("/limits");revalidatePath("/portal");return { ok: true, message: "Лимиты сохранены. Создание новых записей проверяется автоматически." }; } catch (error) { return { ok: false, message: error instanceof ControlPlaneError && error.status === 409 ? "Лимит не может быть меньше уже созданных записей." : "Не удалось сохранить лимиты. Обновите страницу." }; }
}
