"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { getNode, getVPNService, saveVPNSubscriptionName } from "@/lib/control-plane";

export async function saveSubscriptionName(data: FormData) {
  await requireSession();
  const node = String(data.get("node_id") ?? "");
  const id = String(data.get("service_id") ?? "");
  const name = String(data.get("name") ?? "");
  const reset = data.get("operation") === "reset";
  if (!reset && (!name.trim() || [...name].length > 200 || /[\p{Cc}\u2028\u2029]/u.test(name))) {
    return { ok: false, message: "Введите название в одну строку, до 200 символов." };
  }
  try {
    const [detail, service] = await Promise.all([getNode(node), getVPNService(id)]);
    if (detail.node.status === "retired" || service.node_id !== node) return { ok: false, message: "Профиль недоступен для редактирования." };
    const saved = await saveVPNSubscriptionName(id, reset ? "" : name.trim());
    revalidatePath(`/nodes/${node}/control`);
    revalidatePath("/clients");
    return { ok: true, message: reset ? "Исходное название восстановлено. Обновите подписку в приложении." : "Название сохранено. Обновите подписку в приложении.",
      name: saved.subscription_name ?? saved.subscription_default_name ?? saved.name, custom: Boolean(saved.subscription_name) };
  } catch {
    return { ok: false, message: "Не удалось сохранить название. Ваш текст сохранён в форме — попробуйте ещё раз." };
  }
}
