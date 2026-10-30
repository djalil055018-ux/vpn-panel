"use server";

import { Buffer } from "node:buffer";
import { connectionArchive } from "@/lib/connection-archive";
import {
  connectionCredential,
  connectionMetadata,
  type ConnectionArchiveActionResult,
  type ConnectionCredentialActionResult,
  type ConnectionListActionResult,
} from "@/lib/connection-delivery";


import { monthlyBytesFromGiB } from "@/lib/usage-limit";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { authenticatePortalCredential, clearPortalSession, setPortalSession, portalIdentity, portalFetch, PortalError } from "@/lib/portal-api";


export async function portalConnectionsAction(
  clientID: string
): Promise<ConnectionListActionResult> {
  try {
    if (!uuid.test(clientID)) {
      return {
        ok: false,
        message: "Некорректная запись.",
        connections: [],
      };
    }

    if (
      (await portalIdentity()).role !==
      "operator"
    ) {
      return {
        ok: false,
        message:
          "Этот ключ разрешает только просмотр.",
        connections: [],
      };
    }

    /*
     * portalFetch is tenant/session scoped. Full credentials remain on
     * the Web server; the browser receives metadata only.
     */
    const result =
      await portalFetch<{
        connections:
          import("@/lib/control-plane").VPNClientConnection[];
      }>(
        `/clients/${clientID}/connections`
      );

    const connections =
      result.connections ?? [];

    return {
      ok: connections.length > 0,
      message:
        connections.length
          ? `Доступно подключений: ${connections.length}.`
          : "Для клиента пока нет готовых подключений.",
      connections:
        connections.map(
          connectionMetadata
        ),
    };
  } catch {
    return {
      ok: false,
      message:
        "Профили недоступны. Проверьте сеанс и доступ клиента.",
      connections: [],
    };
  }
}

export async function portalConnectionCredentialAction(
  clientID: string,
  serviceID: string
): Promise<ConnectionCredentialActionResult> {
  try {
    if (
      !uuid.test(clientID) ||
      !uuid.test(serviceID)
    ) {
      return {
        ok: false,
        message: "Некорректная запись.",
      };
    }

    if (
      (await portalIdentity()).role !==
      "operator"
    ) {
      return {
        ok: false,
        message:
          "Этот ключ разрешает только просмотр.",
      };
    }

    /*
     * Fresh tenant-scoped effective-access check immediately before
     * disclosure. Selecting a service from stale browser metadata is
     * not sufficient.
     */
    const result =
      await portalFetch<{
        connections:
          import("@/lib/control-plane").VPNClientConnection[];
      }>(
        `/clients/${clientID}/connections`
      );

    const current =
      (result.connections ?? []).find(
        (connection) =>
          connection.service_id === serviceID
      );

    const credential =
      current
        ? connectionCredential(current)
        : undefined;

    if (!credential) {
      return {
        ok: false,
        message:
          "Подключение больше недоступно или профиль ещё не готов.",
      };
    }

    return {
      ok: true,
      message: "Профиль проверен.",
      credential,
    };
  } catch {
    return {
      ok: false,
      message:
        "Профиль недоступен. Проверьте сеанс и доступ клиента.",
    };
  }
}

export async function portalConnectionsArchiveAction(
  clientID: string
): Promise<ConnectionArchiveActionResult> {
  try {
    if (!uuid.test(clientID)) {
      return {
        ok: false,
        message: "Некорректная запись.",
      };
    }

    if (
      (await portalIdentity()).role !==
      "operator"
    ) {
      return {
        ok: false,
        message:
          "Этот ключ разрешает только просмотр.",
      };
    }

    const result =
      await portalFetch<{
        connections:
          import("@/lib/control-plane").VPNClientConnection[];
      }>(
        `/clients/${clientID}/connections`
      );

    const connections =
      result.connections ?? [];

    if (!connections.length) {
      return {
        ok: false,
        message:
          "Нет доступных профилей для архива.",
      };
    }

    return {
      ok: true,
      message: "Архив готов.",
      archive_base64:
        Buffer.from(
          connectionArchive(connections)
        ).toString("base64"),
      filename: "vpn-profiles.zip",
      mime: "application/zip",
    };
  } catch {
    return {
      ok: false,
      message:
        "Архив профилей недоступен. Проверьте сеанс и доступ клиента.",
    };
  }
}

export type PortalActionState = {
 ok: boolean; message: string; subscription?: string };
export async function portalLoginAction(_previous: PortalActionState, form: FormData): Promise<PortalActionState> {
  const credential = String(form.get("credential") ?? "").trim();
  if (!/^vpt1_[A-Za-z0-9_-]{43}$/.test(credential)) return { ok: false, message: "Проверьте ключ доступа." };
  try { const identity = await authenticatePortalCredential(credential); await setPortalSession(credential, identity.expires_at); }
  catch { return { ok: false, message: "Вход недоступен. Проверьте ключ и его срок действия либо повторите попытку позже." }; }
  redirect("/portal");
}
export async function portalLogoutAction() { await clearPortalSession(); redirect("/portal/login"); }
export async function portalInvoiceAction(_previous: PortalActionState, form: FormData): Promise<PortalActionState> {
  const field = (name: string) => String(form.get(name) ?? "").trim();
  const offer = field("offer_id"), client = field("client_id"), key = field("request_key");
  if (![offer, client, key].every(value => uuid.test(value))) return { ok: false, message: "Выберите предложение и клиента." };
  try {
    if ((await portalIdentity()).role !== "operator") return { ok: false, message: "Этот ключ разрешает только просмотр." };
    await portalFetch("/invoices", "POST", { offer_id: offer, client_id: client }, key);revalidatePath("/portal");
    return { ok: true, message: "Счёт создан. Деньги не списаны; доступ появится после подтверждения оплаты." };
  } catch { return { ok: false, message: "Счёт не создан. Проверьте предложение и повторите тот же запрос." }; }
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export async function portalAction(_previous: PortalActionState, form: FormData): Promise<PortalActionState> {
  const field = (name: string) => String(form.get(name) ?? "").trim();
  const operation = field("operation"), id = field("id");
  try {
    const identity = await portalIdentity();
    if (identity.role !== "operator") return { ok: false, message: "Этот ключ разрешает только просмотр." };
    if (!["create-client", "create-plan"].includes(operation) && !uuid.test(id)) return { ok: false, message: "Некорректная запись." };
    if (operation === "create-client") {
      const name = field("name"); if (!name || new TextEncoder().encode(name).length > 100) return { ok: false, message: "Укажите имя до 100 байт." };
      await portalFetch("/clients", "POST", { name });
    } else if (operation === "create-plan" || operation === "update-plan") {
      const name = field("name"), code = field("code").toLowerCase();
      if (!name || new TextEncoder().encode(name).length > 200 || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(code)) return { ok: false, message: "Укажите название и код тарифа латиницей." };
      await portalFetch(operation === "create-plan" ? "/access-plans" : `/access-plans/${id}`, operation === "create-plan" ? "POST" : "PATCH", { name, code, enabled: form.get("enabled") === "yes" });
    } else if (operation === "delete-plan") {
      if (form.get("confirm") !== "yes") return { ok: false, message: "Подтвердите удаление тарифа." };
      await portalFetch(`/access-plans/${id}`, "DELETE");
    } else if (operation === "enable-client" || operation === "disable-client") {
      await portalFetch(`/clients/${id}/${operation === "enable-client" ? "enable" : "disable"}`, "POST", {});
    } else if (operation === "client-expiry") {
      if (form.get("unlimited") === "yes") await portalFetch(`/clients/${id}`, "PATCH", { clear_expires_at: true });
      else { const date = field("date"); if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date)) || new Date(date).toISOString().slice(0, 10) !== date) return { ok: false, message: "Укажите дату или бессрочный доступ." }; await portalFetch(`/clients/${id}`, "PATCH", { expires_at: `${date}T23:59:59+03:00` }); }
    } else if (operation === "client-continuous-limit") {
      const limitBytes = monthlyBytesFromGiB(field("limit_gib"));
      if (limitBytes === null) return { ok: false, message: "Укажите допустимый объём трафика. Ноль снимает ограничение." };
      await portalFetch(`/clients/${id}/continuous-limit`, "PUT", { limit_bytes: limitBytes });
    } else if (operation === "client-limits") {
      const gibRaw = field("monthly_gib"), devicesRaw = field("device_limit"), monthlyBytes = monthlyBytesFromGiB(gibRaw), devices = Number(devicesRaw);
      if (monthlyBytes === null || !/^\d+$/.test(devicesRaw) || !Number.isInteger(devices) || devices > 1000) return { ok: false, message: "Укажите допустимый объём трафика и целое число адресов. Ноль снимает ограничение." };
      await portalFetch(`/clients/${id}/limits`, "PUT", { monthly_bytes: monthlyBytes, device_limit: devices });
    } else if (["add-service", "remove-service", "add-client", "remove-client"].includes(operation)) {
      const target = field("target"); if (!uuid.test(target)) return { ok: false, message: "Выберите запись." };
      await portalFetch(`/access-plans/${id}/${operation.endsWith("service") ? "services" : "clients"}/${target}`, operation.startsWith("add") ? "POST" : "DELETE");
    } else if (operation === "subscription" || operation === "rotate-subscription") {
      let result: { path: string };
      if (operation === "rotate-subscription") result = await portalFetch(`/clients/${id}/subscription/rotate`, "POST", {});
      else { try { result = await portalFetch(`/clients/${id}/subscription`); } catch (error) { if (!(error instanceof PortalError) || error.status !== 404) throw error; result = await portalFetch(`/clients/${id}/subscription`, "POST", {}); } }
      const base = process.env.VPN_PLATFORM_PUBLIC_URL;
      if (!base || !/^\/sub\/[A-Za-z0-9_-]{60,120}$/.test(result.path)) throw new PortalError(503);
      return { ok: true, message: operation === "rotate-subscription" ? "Подписка обновлена. Старая ссылка больше не работает." : "Подписка готова.", subscription: new URL(result.path, base).toString() };
    } else return { ok: false, message: "Неизвестная операция." };
    revalidatePath("/portal");
    return { ok: true, message: "Сохранено. Изменения доступа применяются на затронутых нодах." };
  } catch (error) {
    return { ok: false, message: error instanceof PortalError && error.status === 401 ? "Сеанс или ключ больше не действует. Войдите снова." : error instanceof PortalError && error.status === 404 ? "Запись недоступна для этого ключа." : error instanceof PortalError && error.status === 409 ? "Достигнут лимит, данные изменились или код уже занят. Проверьте ограничения и обновите страницу." : "Не удалось выполнить операцию. Повторите попытку позже." };
  }
}
