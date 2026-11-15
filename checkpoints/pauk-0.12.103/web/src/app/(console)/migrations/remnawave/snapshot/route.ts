import { NextRequest, NextResponse } from "next/server";
import { adminAuthorization, getSession } from "@/lib/auth";

import { normalizeRemnawaveSnapshot } from "@/lib/remnawave-snapshot";

export const runtime = "nodejs";

let processing = false;
const maxSnapshotBytes = 64 * 1024 * 1024;
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const digest = /^[0-9a-f]{64}$/;
const controlPlane = process.env.CONTROL_PLANE_URL ?? "http://127.0.0.1:8080";

function reply(data: object, status: number) {
  return NextResponse.json(data, { status, headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  if ((await getSession())?.role !== "owner") return reply({ error: "Действие доступно владельцу PAUK." }, 403);
  const canonical = new URL(process.env.VPN_PLATFORM_PUBLIC_URL ?? request.nextUrl.origin).origin;
  if (request.headers.get("origin") !== canonical) return reply({ error: "Откройте форму в панели PAUK." }, 403);

  const operation = request.nextUrl.searchParams.get("operation");
  const tenant = request.nextUrl.searchParams.get("tenant") ?? "";
  const fileHash = request.headers.get("x-reviewed-inventory-sha256") ?? "";
  if (!uuid.test(tenant) || (operation !== "preview" && (operation !== "stage" || !digest.test(fileHash)))) {
    return reply({ error: "Выберите владельца PAUK и проверьте снимок перед импортом." }, 400);
  }

  const size = Number(request.headers.get("content-length"));
  if (!request.body || !Number.isSafeInteger(size) || size <= 0 || size > maxSnapshotBytes) {
    return reply({ error: "Выберите файл снимка Remnawave размером до 64 МиБ." }, 413);
  }

  if (processing) return reply({ error: "Обработка другого снимка уже выполняется." }, 429);
  processing = true;
  try {
  const reader = request.body.getReader();
  const raw = new Uint8Array(size);
  let written = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (written + value.byteLength > size) {
        await reader.cancel();
        return reply({ error: "Размер снимка не совпадает с заявленным." }, 400);
      }
      raw.set(value, written);
      written += value.byteLength;
    }
  } catch {
    return reply({ error: "Загрузка снимка прервалась." }, 400);
  } finally {
    reader.releaseLock();
  }
  if (written !== size) return reply({ error: "Снимок передан не полностью." }, 400);
  let normalized: Buffer;
  try {
    normalized = await normalizeRemnawaveSnapshot(raw, request.signal);
  } catch {
    return reply({ error: "Нужен полный JSON-снимок Remnawave 3.4.3 или 3.4.11." }, 400);
  }
  const headers = new Headers({
    "Authorization": "Bearer " + await adminAuthorization(),
    "Content-Type": "application/json",
    "Content-Length": String(normalized.byteLength),
  });
  const path = operation === "preview"
    ? "/api/v1/remnawave/preview"
    : "/api/v1/tenants/" + tenant + "/remnawave-imports";
  if (operation === "stage") {
    headers.set("X-Reviewed-Inventory-SHA256", fileHash);
    headers.set("X-Remnawave-Mode", "stage-held");
  }

  try {
    const input: RequestInit = {
      method: "POST", headers, body: Uint8Array.from(normalized), cache: "no-store",
      redirect: "error", signal: AbortSignal.any([request.signal, AbortSignal.timeout(70_000)]),
    };
    const response = await fetch(controlPlane + path, input);
    if (response.ok) return reply(await response.json(), response.status);
    const errors: Record<number, string> = {
      400: "Снимок неполный, его формат не поддерживается или файл изменился после проверки.",
      403: "Действие доступно владельцу PAUK.",
      404: "Владелец назначения или операция импорта недоступны.",
      409: "Импорт конфликтует с существующим снимком, клиентами или лимитом владельца. Записи не изменены.",
      413: "Файл превышает предел размера снимка.",
    };
    return reply({ error: errors[response.status] ?? "Не удалось выполнить импорт. Обновите список снимков перед повтором." }, response.status);
  } catch {
    return reply({ error: "Панель не получила результат. Обновите список снимков перед повтором." }, 502);
  }
  } finally {
    processing = false;
  }
}
