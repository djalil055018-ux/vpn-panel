"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, deleteVPNClient } from "@/lib/control-plane";
import { PortalError, portalFetch, portalIdentity } from "@/lib/portal-api";

export type ClientDeleteState = { ok: boolean; message: string };
export async function deleteVPNClientAction(_previous: ClientDeleteState, form: FormData): Promise<ClientDeleteState> {
  const id = String(form.get("client_id") ?? "");
  const confirmName = String(form.get("confirm_name") ?? "");
  const audience = form.get("audience");
  if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id) || !confirmName || confirmName.length > 2048 || !["console", "portal"].includes(String(audience))) {
    return { ok: false, message: "Введите точное имя клиента для подтверждения удаления." };
  }
  try {
    if (audience === "portal") {
      if ((await portalIdentity()).role !== "operator") return { ok: false, message: "Недостаточно прав для удаления клиента." };
      await portalFetch(`/clients/${encodeURIComponent(id)}`, "DELETE", { confirm_name: confirmName });
    } else {
      const session = await requireSession();
      if (session.role === "monitor") return { ok: false, message: "Недостаточно прав для удаления клиента." };
      await deleteVPNClient(id, confirmName);
    }
  } catch (error) {
    const status = error instanceof ControlPlaneError || error instanceof PortalError ? error.status : null;
    const body = error instanceof ControlPlaneError ? error.body : "";
    if (status === 403) return { ok: false, message: "Удалить клиента из импорта Remnawave может только владелец панели." };
    if (status === 404) return { ok: false, message: "Клиент уже удалён или недоступен. Обновите список." };
    if (status === 409 && body.includes("client name changed or confirmation differs")) return { ok: false, message: "Имя клиента изменилось. Обновите список и подтвердите актуальное имя." };
    if (body.includes("affected node configuration could not be rebuilt")) return { ok: false, message: "Клиент не удалён: панель не смогла пересобрать конфигурацию одной из нод. Клиент сохранён; проверьте состояние нод и повторите после исправления." };
    if (status === 500) return { ok: false, message: "Клиент не удалён, его запись сохранена. Панель не смогла завершить операцию; проверьте журнал операций и состояние нод." };
    return { ok: false, message: "Удаление не подтверждено. Обновите список, проверьте имя клиента и состояние нод перед повтором." };
  }
  for (const path of ["/clients", "/nodes", "/deployments", "/operations", "/access-plans", "/billing", "/limits", "/portal", "/migrations/remnawave"]) revalidatePath(path);
  revalidatePath("/migrations/remnawave/[id]", "page");
  return { ok: true, message: "Клиент удалён. Отзыв доступа отправлен на затронутые ноды; счета и история импорта сохранены." };
}
