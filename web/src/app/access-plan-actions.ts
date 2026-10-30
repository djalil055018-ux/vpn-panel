"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, createAccessPlan, getAccessPlan, mutateAccessPlan } from "@/lib/control-plane";

export type AccessPlanActionState = { ok: boolean; message: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function accessPlanAction(_previous: AccessPlanActionState, form: FormData): Promise<AccessPlanActionState> {
  await requireSession();
  const field = (name: string) => String(form.get(name) ?? "").trim();
  const tenant = field("tenant_id"), id = field("plan_id"), operation = field("operation");
  if (!uuid.test(tenant) || (operation !== "create" && !uuid.test(id))) return { ok: false, message: "Некорректный владелец или группа доступа." };
  try {
    let nodes = 0;
    if (operation === "create" || operation === "update") {
      const name = field("name"), code = field("code").toLowerCase();
      if (!name || new TextEncoder().encode(name).length > 200 || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(code)) {
        return { ok: false, message: "Укажите название и код: до 64 латинских букв, цифр, дефисов или подчёркиваний." };
      }
      if (operation === "create") await createAccessPlan(tenant, { name, code, enabled: form.has("enabled") });
      else {
        const plan = await getAccessPlan(id);
        if (plan.tenant_id !== tenant) return { ok: false, message: "Группа доступа принадлежит другому владельцу." };
        const enabled = form.has("enabled");
        nodes = (await mutateAccessPlan(id, "PATCH", "", { name, code, ...(enabled !== plan.enabled ? { enabled } : {}) })).rebuilds.length;
      }
    } else {
      const plan = await getAccessPlan(id);
      if (plan.tenant_id !== tenant) return { ok: false, message: "Группа доступа принадлежит другому владельцу." };
      if (operation === "delete") {
        if (field("confirm") !== "yes") return { ok: false, message: "Подтвердите удаление группы." };
        nodes = (await mutateAccessPlan(id, "DELETE")).rebuilds.length;
      } else {
        const target = field("target_id");
        if (!uuid.test(target)) return { ok: false, message: "Выберите сервис или клиента." };
        const options: Record<string, ["POST" | "DELETE", string]> = {
          "add-service": ["POST", "services"], "remove-service": ["DELETE", "services"],
          "assign-client": ["POST", "clients"], "remove-client": ["DELETE", "clients"],
        };
        const route = options[operation];
        if (!route) return { ok: false, message: "Неизвестная операция." };
        nodes = (await mutateAccessPlan(id, route[0], `/${route[1]}/${encodeURIComponent(target)}`)).rebuilds.length;
      }
    }
    revalidatePath("/access-plans"); revalidatePath("/clients"); revalidatePath("/nodes"); revalidatePath("/deployments");
    return { ok: true, message: nodes ? `Сохранено. Обновления отправлены на ноды: ${nodes}. Применение можно проверить в разделе «Ноды».` : "Изменения сохранены." };
  } catch (error) {
    let message = "Не удалось сохранить изменение. Обновите страницу и повторите попытку.";
    if (error instanceof ControlPlaneError) {
      if (error.status === 409) message = "Код уже занят или данные изменились одновременно. Обновите страницу и проверьте код.";
      if (error.status === 404) message = "Группа, сервис или клиент недоступны. Обновите страницу.";
      if (error.status === 400) message = "Проверьте введённые данные.";
    }
    return { ok: false, message };
  }
}
