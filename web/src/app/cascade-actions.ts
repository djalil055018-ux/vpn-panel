"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, deleteCascade, getCascade, saveCascade } from "@/lib/control-plane";

export type CascadeActionState = { ok: boolean; message: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export async function cascadeAction(form: FormData): Promise<CascadeActionState> {
  const session = await requireSession();
  if (session.role === "monitor") return { ok: false, message: "Изменять каскады может администратор или владелец." };
  const field = (name: string) => String(form.get(name) ?? "").trim();
  const tenant = field("tenant_id"), id = field("cascade_id"), operation = field("operation");
  if (!uuid.test(tenant) || (id && !uuid.test(id)) || !["save", "delete"].includes(operation) || (operation === "delete" && !id)) return { ok: false, message: "Некорректный запрос. Обновите страницу." };
  try {
    const existing = id ? await getCascade(id) : null;
    if (existing && existing.tenant_id !== tenant) return { ok: false, message: "Каскад принадлежит другому владельцу." };
    let result;
    if (operation === "delete") {
      if (field("confirm") !== "yes") return { ok: false, message: "Подтвердите удаление каскада." };
      result = await deleteCascade(id);
    } else {
      const name = field("name"), plan = field("plan_id"), entry = field("entry_service_id"), exit = field("exit_service_id"), port = field("entry_port"), enabled = form.has("enabled");
      if (!name || [...name].length > 128 || /[\p{Cc}\p{Cf}]/u.test(name) || ![plan, entry, exit].every(value => uuid.test(value)) || entry === exit || !/^\d{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535 || Number(port) === 10085) return { ok: false, message: "Проверьте название, группу, два разных сервера и свободный порт от 1 до 65535. Порт 10085 зарезервирован." };
      const runtimeChange = !existing || existing.enabled !== enabled || existing.plan_id !== plan || existing.entry_service_id !== entry || existing.exit_service_id !== exit || existing.entry_port !== Number(port);
      if (runtimeChange && (enabled || existing?.enabled) && field("apply") !== "yes") return { ok: false, message: "Подтвердите применение конфигурации на серверах." };
      result = await saveCascade(tenant, id || null, { name, plan_id: plan, entry_service_id: entry, exit_service_id: exit, entry_port: Number(port), enabled });
    }
    for (const path of ["/cascades", "/nodes", "/deployments", "/clients"]) revalidatePath(path);
    return { ok: true, message: operation === "delete" ? "Каскад удалён. Обычные профили сохранены." : result.rebuilds.length ? "Сохранено. Ожидаем применения на обоих серверах." : "Настройки сохранены." };
  } catch (error) {
    let message = "Связь прервалась. Обновите список, чтобы проверить результат перед повтором.";
    if (error instanceof ControlPlaneError) {
      if (error.status === 409) message = "Каскад не сохранён. Проверьте свободный порт, включённые VLESS TCP REALITY сервисы, агент от 0.2.34 и Xray от 26.9.9 на обоих серверах.";
      else if (error.status === 404) message = "Каскад, группа или сервер больше недоступны. Обновите страницу.";
      else if (error.status === 403) message = "Недостаточно прав для изменения каскадов.";
      else if (error.status === 400) message = "Проверьте введённые данные.";
    }
    return { ok: false, message };
  }
}
