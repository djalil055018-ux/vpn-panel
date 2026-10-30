"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, deleteNode } from "@/lib/control-plane";

export async function deleteNodeAction(_previous: { message: string; decommissioning?: boolean }, form: FormData): Promise<{ message: string; decommissioning?: boolean }> {
  const session = await requireSession();
  if (session.role !== "owner") return { message: "Удалить ноду может только владелец панели." };
  const id = String(form.get("node_id") ?? "");
  const name = String(form.get("confirm_name") ?? "");
  const stopped = form.get("server_stopped") === "yes";
  const decommissionOnline = form.get("decommission_online") === "yes";
  if (!/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id) || !name || name.length > 2048 || (!stopped && !decommissionOnline)) {
    return { message: "Введите точное имя ноды и выберите безопасный способ остановки VPN." };
  }
  try {
    const result = await deleteNode(id, name, { serverStopped: stopped, decommissionOnline });
    if (result.decommissioning) {
      for (const path of ["/nodes", "/clients", "/access-plans", "/operations", "/deployments", `/nodes/${id}`, `/nodes/${id}/control`]) revalidatePath(path);
      return { message: `Панель отключила VPN-сервисы и отправила пустую конфигурацию generation ${result.generation}. Дождитесь её применения, обновите состояние и нажмите удаление ещё раз.`, decommissioning: true };
    }
    if (!result.deleted || result.node_id !== id) return { message: "Удаление не подтверждено. Обновите список перед повтором." };
  } catch (error) {
    if (error instanceof ControlPlaneError && error.status === 403) return { message: "Удалить ноду может только владелец панели." };
    if (error instanceof ControlPlaneError && error.status === 404) return { message: "Нода не найдена. Обновите список." };
    if (error instanceof ControlPlaneError && error.status === 409 && error.body.includes("node name changed or confirmation differs")) return { message: "Название ноды изменилось или подтверждение не совпало. Обновите страницу и введите актуальное название." };
    if (error instanceof ControlPlaneError && error.status === 409 && error.body.includes("node is still applying the empty VPN configuration or has unresolved work")) return { message: "Нода ещё применяет пустую VPN-конфигурацию или выполняет незавершённую операцию. Обновите состояние и повторите после её завершения." };
    return { message: "Ответ об удалении не получен. Проверьте список удалённых нод; повторный запрос безопасен." };
  }
  for (const path of ["/nodes", "/agent-updates", "/core-updates", "/operations", "/clients", "/access-plans", "/deployments"]) revalidatePath(path);
  revalidatePath(`/nodes/${id}`);
  revalidatePath(`/nodes/${id}/control`);
  redirect("/nodes?deleted_notice=1");
}
