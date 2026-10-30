import "server-only";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { createHash } from "node:crypto";
import { customerSessionCookieName as cookieName, setCustomerSessionCookie, clearCustomerSessionCookie } from "@/lib/customer-session-cookie";

const maxBody = 2_800_000;
const headers = { "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" };
const windows = new Map<string, number[]>();

function destination(method: string, parts: string[]): string | null {
  if (parts.some(part => part === "." || part === "..")) return null;
  const path = parts.join("/");
  if (method === "POST" && path === "session") return "/api/web/session";
  if (method === "GET" && path === "profile") return "/api/web/auth/status";
  if (method === "POST" && /^(login|register)$/.test(path)) return `/api/web/auth/${path}`;
  if (method === "GET" && /^email\/(overview|orders)$/.test(path)) return `/api/web/${path}`;
  if (method === "POST" && /^email\/(context|orders|native\/devices)$/.test(path)) return `/api/web/${path}`;
  if (method === "POST" && /^email\/orders\/[A-Za-z0-9_-]{8,64}\/checkout$/.test(path)) return `/api/web/${path}`;
  if (method === "POST" && /^email\/payments\/[A-Za-z0-9_-]{8,64}\/(check|cancel)$/.test(path)) return `/api/web/${path}`;
  if (method === "POST" && /^payments\/[A-Za-z0-9_-]{8,64}\/(check|cancel)$/.test(path)) return `/api/web/customer/${path}`;
  if (method === "POST" && /^email\/(native\/extra-device|accounts\/[1-9][0-9]{0,15}\/extra-device|device-purchases\/[A-Za-z0-9_-]{8,64}\/retry)$/.test(path)) return `/api/web/${path}`;
  if ((method === "GET" || method === "DELETE") && /^email\/accounts\/[1-9][0-9]{0,15}\/devices$/.test(path)) return `/api/web/${parts.slice(1).join("/")}`;
  if (method === "DELETE" && parts.length === 5 && /^email\/accounts\/[1-9][0-9]{0,15}\/devices\//.test(path) && /^[A-Za-z0-9_.:-]{1,255}$/.test(parts[4])) return `/api/web/accounts/${parts[2]}/devices/${encodeURIComponent(parts[4])}`;
  if (method === "POST" && /^email\/accounts\/[1-9][0-9]{0,15}\/revoke$/.test(path)) return `/api/web/${parts.slice(1).join("/")}`;
  if (method === "DELETE" && /^email\/accounts\/[1-9][0-9]{0,15}$/.test(path)) return `/api/web/email/accounts/${parts[2]}`;
  if (method === "DELETE" && /^accounts\/[1-9][0-9]{0,15}$/.test(path)) return `/api/web/customer/accounts/${parts[1]}`;
  if (method === "POST" && /^(logout)$/.test(path)) return `/api/web/auth/${path}`;
  if (method === "POST" && path === "telegram/challenge") return "/api/web/auth/telegram/challenge";
  if (method === "POST" && /^telegram\/poll\/[A-Za-z0-9_-]{16,64}$/.test(path)) return `/api/web/auth/telegram/challenge/${parts[2]}`;
  if (method === "GET" && /^(overview|orders|referral)$/.test(path)) return `/api/web/customer/${path}`;
  if (method === "POST" && /^(context|native\/devices|orders|trial|promo|referral\/(claim|withdraw|shop))$/.test(path)) return `/api/web/customer/${path}`;
  if (method === "POST" && /^(native\/extra-device|device-purchases\/[A-Za-z0-9_-]{8,64}\/retry)$/.test(path)) return `/api/web/customer/${path}`;
  if (method === "POST" && /^orders\/[A-Za-z0-9_-]{8,64}\/(checkout|receipt)$/.test(path)) return `/api/web/customer/${path}`;
  if ((method === "GET" || method === "DELETE") && /^accounts\/[1-9][0-9]{0,15}\/devices$/.test(path)) return `/api/web/customer/${path}`;
  if (method === "DELETE" && parts.length === 4 && /^accounts\/[1-9][0-9]{0,15}\/devices\//.test(path) && /^[A-Za-z0-9_.:-]{1,255}$/.test(parts[3])) return `/api/web/customer/accounts/${parts[1]}/devices/${encodeURIComponent(parts[3])}`;
  if (method === "POST" && /^accounts\/[1-9][0-9]{0,15}\/(revoke|extra-device)$/.test(path)) return `/api/web/customer/${path}`;
  if (method === "GET" && path === "setup") return "/api/web/setup";
  if ((method === "GET" || method === "POST") && path === "support/tickets") return "/api/web/support/tickets";
  if (method === "GET" && /^support\/tickets\/[A-Za-z0-9_-]{8,64}$/.test(path)) return `/api/web/${path}`;
  if (method === "POST" && /^support\/tickets\/[A-Za-z0-9_-]{8,64}\/messages$/.test(path)) return `/api/web/${path}`;
  return null;
}

function failure(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers });
}

async function boundedBody(body: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > maxBody) { await reader.cancel(); throw new Error("size"); }
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally { reader.releaseLock(); }
}

export async function customerBridge(request: Request, parts: string[]) {
  const method = request.method;
  const path = destination(method, parts);
  if (!path) return failure("Страница не найдена", 404);
  let origin: URL;
  let publicOrigin: URL;
  try {
    origin = new URL(process.env.CUSTOMER_COMMERCE_ORIGIN || "");
    publicOrigin = new URL(process.env.VPN_PLATFORM_PUBLIC_URL || "");
    if (origin.protocol !== "https:" || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash) throw new Error("origin");
  } catch { return failure("Кабинет оплаты пока не настроен. Обратитесь в поддержку", 503); }
  if (method !== "GET" && (request.headers.get("origin") !== publicOrigin.origin || request.headers.get("x-pauk-customer") !== "1")) {
    return failure("Обновите страницу и повторите действие", 403);
  }
  const jar = await cookies();
  let token = jar.get(cookieName)?.value;
  if (token && !/^[A-Za-z0-9_-]{32,256}$/.test(token)) token = undefined;
  const key = createHash("sha256").update(token || request.headers.get("x-real-ip") || "anonymous").digest("hex");
  const now = Date.now();
  const attempts = (windows.get(key) || []).filter(at => at > now - 60_000);
  if (attempts.length >= 60) return failure("Слишком много запросов. Подождите минуту", 429);
  attempts.push(now); windows.delete(key); windows.set(key, attempts);
  while (windows.size > 4096) windows.delete(windows.keys().next().value!);
  if (!token && path !== "/api/web/session" && path !== "/api/web/auth/login") return failure("Войдите в личный кабинет", 401);
  if (path === "/api/web/session" && token) return NextResponse.json({ ok: true }, { headers });
  let body: string | undefined;
  if (method !== "GET") {
    if (!request.headers.get("content-type")?.startsWith("application/json")) return failure("Нужен запрос JSON", 415);
    try {
      body = await boundedBody(request.body);
      const parsed = JSON.parse(body || "{}");
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("body");
    } catch { return failure("Проверьте данные: размер файла не должен превышать 2 МБ", 400); }
  }
  const upstreamHeaders: Record<string, string> = { "X-Pauk-Bridge": process.env.CUSTOMER_PORTAL_BRIDGE_SECRET || "", "X-Pauk-Client": key, Accept: "application/json", "Content-Type": "application/json" };
  if (token) upstreamHeaders.Authorization = `Bearer ${token}`;
  const idempotency = request.headers.get("idempotency-key");
  if (idempotency && /^[0-9a-f-]{36}$/i.test(idempotency)) upstreamHeaders["Idempotency-Key"] = idempotency;
  const poll = parts[0] === "telegram" && parts[1] === "poll";
  try {
    const response = await fetch(new URL(path, origin), { method: poll ? "GET" : method, headers: upstreamHeaders,
      body: poll || method === "GET" ? undefined : body, cache: "no-store", redirect: "error", signal: AbortSignal.timeout(25_000) });
    const value = JSON.parse(await boundedBody(response.body));
    if (!response.ok) {
      if (response.status === 401) clearCustomerSessionCookie(jar);
      const deletionErrors: Record<string, string> = {
        subscription_payment_pending: "У этой подписки есть незавершённая оплата. Откройте «Платежи» и завершите её или обратитесь в поддержку.",
        subscription_busy: "Подписка сейчас обновляется. Повторите удаление через несколько секунд.",
        subscription_deleted: "Подписка уже удаляется или удалена. Обновите кабинет.",
        subscription_delete_pending: "Удаление пока не подтверждено сервером. Повторите запрос: повторное удаление безопасно.",
        subscription_unavailable: "Подписка недоступна. Обновите кабинет или обратитесь в поддержку. Оплачивать этот заказ пока не нужно.",
        subscription_changed: "Параметры подписки изменились. Обновите кабинет перед оплатой.",
        subscription_renewal_unnecessary: "Эта подписка не ограничена по сроку. Продлевать её не нужно.",
        payment_target_check_unavailable: "Не удалось проверить подписку. Повторите попытку позже; повторно оплачивать заказ не нужно.",
        payment_method_unavailable: "Этот способ оплаты отключён. Выберите доступный способ оплаты или обратитесь в поддержку с номером заказа.",
        payment_not_pending: "Этот заказ больше не ожидает оплаты. Обновите его статус; повторно платить не нужно.",
        payment_cancel_not_allowed: "По заказу уже есть оплата, чек на проверке или он закрыт. Обновите статус; повторно платить не нужно.",
        payment_busy: "Заказ сейчас обновляется. Повторите отмену через несколько секунд.",
      };
      const deletionCode = value?.detail?.code;
      if (typeof deletionCode === "string" && deletionErrors[deletionCode]) return failure(deletionErrors[deletionCode], response.status >= 500 ? 502 : response.status);
      const safeErrors: Record<number, string> = { 400: "Проверьте введённые данные", 401: "Войдите в личный кабинет", 403: "Недостаточно прав для этого действия", 404: "Запись не найдена", 409: "Операция сейчас недоступна. Проверьте условия и повторите попытку", 422: "Проверьте заполненные поля", 429: "Слишком много запросов. Подождите минуту" };
      return failure(parts[0] === "login" && response.status === 401 ? "Неверный email или пароль" : parts[0] === "register" && response.status === 409 ? "Проверьте email или войдите в существующий аккаунт" : safeErrors[response.status] || "Сервис временно недоступен. Повторите позже", response.status >= 500 ? 502 : response.status);
    }
    if (typeof value.access_token === "string" && /^[A-Za-z0-9_-]{32,256}$/.test(value.access_token)) {
      setCustomerSessionCookie(jar, value.access_token);
    }
    delete value.access_token;
    delete value.is_admin;
    if (value.profile) delete value.profile.is_admin;
    if (parts[0] === "logout") clearCustomerSessionCookie(jar);
    return NextResponse.json(value, { headers });
  } catch { return failure("Не удалось получить ответ. Повторите попытку; повторно оплачивать заказ не нужно", 502); }
}
