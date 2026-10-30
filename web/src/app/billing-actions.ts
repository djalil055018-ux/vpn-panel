"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { billingCurrencies, parseMinorUnits } from "@/lib/billing-values";
import { billingInvoiceAction, createBillingInvoice, getBillingInvoices, getBillingOffers, saveBillingOffer, ControlPlaneError } from "@/lib/control-plane";
export type BillingActionState = { ok: boolean; message: string };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export async function billingAction(_previous: BillingActionState, form: FormData): Promise<BillingActionState> {
  await requireSession();
  const field = (name: string) => String(form.get(name) ?? "").trim();
  const tenant = field("tenant_id"), operation = field("operation"), id = field("id");
  if (!uuid.test(tenant)) return { ok: false, message: "Выберите владельца." };
  try {
    if (operation === "create-offer" || operation === "update-offer") {
      const name = field("name"), amount = parseMinorUnits(field("amount")), currency = field("currency"), days = Number(field("days")), plan = field("plan_id");
      if (!name || new TextEncoder().encode(name).length > 200 || amount === null || !billingCurrencies.includes(currency) || !Number.isInteger(days) || days < 1 || days > 3650 || (operation === "create-offer" ? !uuid.test(plan) : !uuid.test(id))) return { ok: false, message: "Проверьте название, цену, валюту и срок от 1 до 3650 дней." };
      if (operation === "update-offer" && !(await getBillingOffers(tenant)).some(offer => offer.id === id)) return { ok: false, message: "Предложение недоступно." };
      await saveBillingOffer(tenant, operation === "create-offer" ? null : id, { ...(operation === "create-offer" ? { plan_id: plan } : {}), name, amount_minor: amount, currency, duration_days: days, enabled: form.get("enabled") === "yes" });
    } else if (operation === "create-invoice") {
      const offer = field("offer_id"), client = field("client_id"), key = field("request_key");
      if (!uuid.test(offer) || !uuid.test(client) || !uuid.test(key)) return { ok: false, message: "Выберите предложение и клиента." };
      await createBillingInvoice(tenant, { offer_id: offer, client_id: client }, key);
    } else if (operation === "settle" || operation === "void") {
      if (!uuid.test(id) || form.get("confirm") !== "yes") return { ok: false, message: "Подтвердите действие со счётом." };
      if (!(await getBillingInvoices(tenant)).some(invoice => invoice.id === id)) return { ok: false, message: "Счёт недоступен для выбранного владельца." };
      const reference = field("reference");
      if (operation === "settle" && (!reference || new TextEncoder().encode(reference).length > 200)) return { ok: false, message: "Укажите идентификатор полученной оплаты." };
      await billingInvoiceAction(id, operation, reference);
    } else return { ok: false, message: "Неизвестная операция." };
    for (const path of ["/billing", "/portal", "/clients", "/access-plans", "/operations"]) revalidatePath(path);
    return { ok: true, message: operation === "settle" ? "Оплата подтверждена. Оплаченный период добавлен; изменения доступа отправлены на нужные ноды." : "Сохранено." };
  } catch (error) {
    return { ok: false, message: error instanceof ControlPlaneError && error.status === 409 ? "Состояние счёта или ключ запроса уже изменились. Обновите страницу перед повтором." : "Операция не завершена. Проверьте данные и состояние нод; повторите тот же запрос." };
  }
}
