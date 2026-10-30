"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { createWebhookEndpoint, deleteWebhookEndpoint, getWebhookEndpoints, getWebhookDeliveries, retryWebhookDelivery, setWebhookEnabled } from "@/lib/control-plane";
import { webhookEvents, webhookURL } from "@/lib/webhook-values";
export type WebhookState = { ok: boolean; message: string; secret?: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export async function webhookAction(_prior: WebhookState, form: FormData): Promise<WebhookState> {
  await requireSession();const field = (key: string) => String(form.get(key) ?? "").trim();const tenant = field("tenant_id"), operation = field("operation"), id = field("id");if (!uuid.test(tenant)) return { ok: false, message: "Выберите владельца." };
  try {
    if (operation === "create") { const name = field("name"), url = field("url"), events = form.getAll("events").map(String);if (!name || new TextEncoder().encode(name).length > 100 || !webhookURL(url) || events.length < 1 || events.length > 2 || events.some(event => !webhookEvents.some(allowed => allowed.value === event))) return { ok: false, message: "Укажите название, HTTPS-адрес без параметров и события." };const out = await createWebhookEndpoint(tenant, { name, url, events });revalidatePath("/webhooks");return { ok: true, message: "Получатель создан выключенным. Сохраните секрет и настройте проверку подписи у получателя, затем включите доставку.", secret: out.signing_secret }; }
    if (!uuid.test(id)) return { ok: false, message: "Некорректная запись." };
    if (operation === "enable" || operation === "disable") { if (!(await getWebhookEndpoints(tenant)).some(endpoint => endpoint.id === id)) return { ok: false, message: "Получатель недоступен." };if (operation === "enable" && field("confirm") !== "yes") return { ok: false, message: "Подтвердите, что получатель настроен." };await setWebhookEnabled(id, operation === "enable"); }
    else if (operation === "retry") { if (!(await getWebhookDeliveries(tenant)).some(delivery => delivery.id === id)) return { ok: false, message: "Доставка недоступна." };await retryWebhookDelivery(id); }
    else if (operation === "delete") { if (field("confirm") !== "yes" || !(await getWebhookEndpoints(tenant)).some(endpoint => endpoint.id === id && !endpoint.enabled)) return { ok: false, message: "Выключите получателя и подтвердите удаление истории." };await deleteWebhookEndpoint(id); }
    else return { ok: false, message: "Неизвестная операция." };
    revalidatePath("/webhooks");return { ok: true, message: operation === "delete" ? "Получатель и его история доставки удалены." : operation === "disable" ? "Доставка выключена. Ожидающие попытки отменены; уже отправляемый запрос может завершиться." : operation === "retry" ? "Доставка возвращена в очередь." : "Доставка включена для новых событий." };
  } catch { return { ok: false, message: "Операция не завершена. Проверьте адрес, состояние получателя и службы доставки." }; }
}
