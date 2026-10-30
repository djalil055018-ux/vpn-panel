"use server";

import { monthlyBytesFromGiB } from "@/lib/usage-limit";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { saveVPNClientLimits, saveVPNClientContinuousLimit } from "@/lib/control-plane";

export type ClientUsageState = { ok: boolean; message: string };

export async function clientUsageAction(_previous: ClientUsageState, form: FormData): Promise<ClientUsageState> {
  await requireSession();
  const id = String(form.get("client_id") ?? "").trim();
  const policy = String(form.get("reset_policy") ?? "MONTH");
  const continuous = policy === "NO_RESET";
  const gibRaw = String(form.get(continuous ? "limit_gib" : "monthly_gib") ?? "").trim();
  const devicesRaw = String(form.get("device_limit") ?? "").trim();
  const monthlyBytes = monthlyBytesFromGiB(gibRaw), devices = Number(devicesRaw);
  if (!/^[0-9a-f-]{36}$/i.test(id) || !["MONTH", "NO_RESET"].includes(policy) || monthlyBytes === null || (!continuous && (!/^\d+$/.test(devicesRaw) || !Number.isInteger(devices) || devices < 0 || devices > 1000))) {
    return { ok: false, message: "Укажите допустимый объём трафика и целое число адресов до 1000. Ноль снимает ограничение." };
  }
  try {
    if (continuous) await saveVPNClientContinuousLimit(id, monthlyBytes);
    else await saveVPNClientLimits(id, monthlyBytes, devices);
    for (const path of ["/clients", "/nodes", "/deployments", "/operations", "/incidents"]) revalidatePath(path);
    return { ok: true, message: "Лимиты сохранены. Доступ на нодах обновляется автоматически." };
  } catch {
    return { ok: false, message: "Не удалось сохранить лимиты. Проверьте состояние нод и повторите попытку." };
  }
}
