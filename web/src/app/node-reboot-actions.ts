"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, requestNodeReboot } from "@/lib/control-plane";

export type NodeRebootActionState = { ok: boolean; message: string };

export async function requestNodeRebootAction(_previous: NodeRebootActionState, form: FormData): Promise<NodeRebootActionState> {
  const session = await requireSession();
  if (session.role !== "owner") return { ok: false, message: "Перезагружать серверы может только владелец панели." };
  const id = String(form.get("node_id") ?? "").trim();
  const name = String(form.get("confirm_name") ?? "");
  if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id) || !name || name.length > 80 || form.get("confirm_reboot") !== "yes") {
    return { ok: false, message: "Введите точное название сервера и подтвердите перезагрузку." };
  }
  try {
    const result = await requestNodeReboot(id, name);
    if (!result.queued || result.job.node_id !== id || result.job.status !== "queued") {
      return { ok: false, message: "Панель не подтвердила запрос. Проверьте состояние сервера." };
    }
    for (const path of ["/nodes", "/dashboard", "/operations", `/nodes/${id}`, `/nodes/${id}/control`]) revalidatePath(path);
    return { ok: true, message: `Запрос принят. VPN на сервере отключится, перезагрузка начнётся примерно через ${result.delay_seconds} секунд.` };
  } catch (error) {
    if (error instanceof ControlPlaneError) {
      if (error.status === 403) return { ok: false, message: "Перезагружать серверы может только владелец панели." };
      if (error.status === 404) return { ok: false, message: "Сервер не найден. Обновите страницу." };
      if (error.status === 409 && error.body.includes("name changed")) return { ok: false, message: "Название изменилось. Обновите страницу и повторите." };
      if (error.status === 409 && error.body.includes("update the node agent")) return { ok: false, message: "Для сервера ещё не установлен агент с поддержкой перезагрузки." };
      if (error.status === 409 && error.body.includes("online, healthy and synchronized")) return { ok: false, message: "Сервер должен быть на связи, исправен и синхронизирован." };
      if (error.status === 409 && error.body.includes("active operation")) return { ok: false, message: "На сервере уже выполняется операция или запрос перезагрузки." };
      if (error.status === 409 && error.body.includes("recently")) return { ok: false, message: "Подождите 15 минут после предыдущей перезагрузки." };
    }
    return { ok: false, message: "Не удалось отправить запрос перезагрузки. Повторите проверку состояния сервера." };
  }
}
