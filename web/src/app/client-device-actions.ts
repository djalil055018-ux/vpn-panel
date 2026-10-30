"use server";

import { requireSession } from "@/lib/auth";
import { ControlPlaneError, getRegisteredDevices, setRegisteredDeviceLimit, deleteRegisteredDevice } from "@/lib/control-plane";
import type { DeviceActionResult } from "@/lib/client-devices";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function readClientDevices(id: string): Promise<DeviceActionResult> {
  const session = await requireSession();
  if (session.role === "monitor" || !uuid.test(id)) return { ok: false, message: "Нет доступа к устройствам этого клиента." };
  try { return { ok: true, message: "", data: await getRegisteredDevices(id) }; }
  catch { return { ok: false, message: "Не удалось загрузить устройства. Повторите попытку." }; }
}

export async function saveClientDeviceLimit(form: FormData): Promise<DeviceActionResult> {
  const session = await requireSession();
  if (session.role === "monitor") return { ok: false, message: "Недостаточно прав для изменения лимита." };
  const id = String(form.get("client_id") ?? "");
  const raw = String(form.get("limit") ?? "").trim(), limit = Number(raw);
  if (!uuid.test(id) || !/^\d+$/.test(raw) || !Number.isSafeInteger(limit) || limit > 1000) return { ok: false, message: "Укажите целое число от 0 до 1000. Ноль — без лимита." };
  try { return { ok: true, message: limit ? "Лимит привязанных устройств сохранён." : "Ограничение устройств выключено.", data: await setRegisteredDeviceLimit(id, limit) }; }
  catch (error) {
    return { ok: false, message: error instanceof ControlPlaneError && error.status === 409
      ? "Уже привязано больше устройств. Удалите лишние привязки и сохраните лимит ещё раз."
      : "Не удалось сохранить лимит. Обновите список устройств и повторите попытку." };
  }
}

export async function removeClientDevice(form: FormData): Promise<DeviceActionResult> {
  const session = await requireSession();
  if (session.role === "monitor") return { ok: false, message: "Недостаточно прав для удаления привязки." };
  const id = String(form.get("client_id") ?? ""), deviceID = String(form.get("device_id") ?? "");
  if (!uuid.test(id) || !uuid.test(deviceID)) return { ok: false, message: "Не удалось определить устройство." };
  try { return { ok: true, message: "Привязка удалена. Место для нового устройства свободно.", data: await deleteRegisteredDevice(id, deviceID) }; }
  catch { return { ok: false, message: "Не удалось удалить привязку. Обновите список и повторите попытку." }; }
}
