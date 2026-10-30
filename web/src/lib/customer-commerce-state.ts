export type PaymentState = {
  status: string;
  payment_unavailable?: boolean;
  payment_unavailable_message?: string;
  payment_form?: unknown;
  payment_url?: string;
  requisites?: string;
};

export function pendingPayment(status: string) {
  return ["PENDING", "PAYMENT_PENDING", "WAITING_PAYMENT"].includes(status);
}

export function mergePayment<T extends PaymentState>(current: T, updated: Partial<T> & Pick<T, "status">): T {
  const result = { ...current, ...updated };
  if (updated.payment_form && updated.payment_unavailable !== true) {
    result.payment_unavailable = false;
    delete result.payment_unavailable_message;
  }
  if (!pendingPayment(result.status) || result.payment_unavailable) {
    delete result.payment_form;
    delete result.payment_url;
    delete result.requisites;
  }
  return result;
}

export function subscriptionName(account: { id: number; name: string }): string {
  if (/^(tg_\d+_[A-Za-z0-9_]+|web_[a-z0-9]{1,12}_[a-z0-9]{1,16})$/.test(account.name)) {
    return `${account.name.endsWith("_trial") ? "Пробная подписка" : "Подписка PAUK"} №${account.id}`;
  }
  return account.name || `Подписка PAUK №${account.id}`;
}

export function orderPurpose(order: { kind?: string; purpose?: string }): string {
  return order.kind === "device" ? "Дополнительное устройство" : order.purpose === "renew" ? "Продление подписки" : order.purpose === "new" ? "Новая подписка" : "Подписка VPN";
}

export function subscriptionExpiry(account: { unavailable?: boolean; delete_pending?: boolean; expire_at?: string }): string {
  if (account.delete_pending) return "Удаление ещё не подтверждено — повторите запрос";
  if (account.unavailable) return "Данные подписки пока недоступны";
  if (!account.expire_at) return "Без ограничения по сроку";
  const value = new Date(account.expire_at);
  if (!Number.isFinite(value.getTime())) return "Срок подписки уточняется";
  return `Действует до ${new Intl.DateTimeFormat("ru", { day: "numeric", month: "short", year: "numeric", timeZone: "Europe/Moscow" }).format(value)}`;
}
