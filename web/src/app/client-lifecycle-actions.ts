"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, updateVPNClientLifecycle } from "@/lib/control-plane";
export type ClientLifecycleState = { ok: boolean; message: string };
export async function clientLifecycleAction(_previous: ClientLifecycleState, form: FormData): Promise<ClientLifecycleState> {
  await requireSession();
  const field = (name: string) => String(form.get(name) ?? "").trim();
  const id = field("client_id"), operation = field("operation");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return { ok: false, message: "Некорректный клиент." };
  try {
    if (operation === "rename") {
      const name = field("name");
      if (!name || Array.from(name).length > 100) return { ok: false, message: "Введите имя клиента длиной до 100 символов." };
      await updateVPNClientLifecycle(id, { name });
    }
    else if (operation === "enable" || operation === "disable") await updateVPNClientLifecycle(id, { status: operation === "enable" ? "active" : "disabled" });
    else if (operation === "expiry") {
      const date = field("date");
      if (form.get("unlimited") === "yes") await updateVPNClientLifecycle(id, { clear_expires_at: true });
      else {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date)) || new Date(date).toISOString().slice(0, 10) !== date) return { ok: false, message: "Укажите дату окончания или выберите бессрочный доступ." };
        await updateVPNClientLifecycle(id, { expires_at: `${date}T23:59:59+03:00` });
      }
    } else return { ok: false, message: "Неизвестная операция." };
    for (const path of ["/clients", "/nodes", "/deployments", "/operations"]) revalidatePath(path);
    return { ok: true, message: operation === "rename" ? "Имя клиента изменено." : "Сохранено. Изменение доступа отправлено на затронутые ноды. Включение клиента не продлевает истёкший срок." };
  } catch (error) {
    if (error instanceof ControlPlaneError) {
      if (error.status === 400) return { ok: false, message: "Проверьте имя клиента и срок действия." };
      if (error.status === 403) return { ok: false, message: "Недостаточно прав для изменения клиента." };
      if (error.status === 404) return { ok: false, message: "Клиент не найден. Обновите список." };
      if (error.status === 409) return { ok: false, message: "Изменение конфликтует с состоянием переноса клиента. Обновите страницу и проверьте его статус." };
      if (error.status >= 500) return { ok: false, message: "Панель не сохранила изменение; данные клиента остались без изменений. Проверьте журнал операций и состояние нод." };
    }
    return { ok: false, message: "Изменение не сохранено. Проверьте соединение с панелью и повторите попытку." };
  }
}
