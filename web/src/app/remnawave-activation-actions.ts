"use server";

import { createConnection } from "node:net";
import { requireSession } from "@/lib/auth";
import { revalidatePath } from "next/cache";

export type MigrationActionState = { status: string; message: string };
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const digestPattern = /^[0-9a-f]{64}$/;

const messages: Record<string, string> = {
  ok: "Клиенты перенесены. Ноды применят новые настройки автоматически.",
  stale: "Снимок изменился или перенос уже выполнен. Обновите страницу.",
  missing: "Снимок не найден.",
  plan_unavailable: "Выберите включённую группу, в которой есть хотя бы один доступный сервис с применённой конфигурацией.",
  client_changed: "Данные сохранённых клиентов изменились. Проверьте снимок и карточки клиентов.",
  invalid_timezone: "Укажите часовой пояс по базе IANA, например UTC или Europe/Moscow.",
  invalid_policy: "В снимке есть несовместимые правила трафика или истечения срока.",
  identity_conflict: "Найдены существующие имена или Telegram ID. Перенос остановлен, чтобы не заменить чужую запись.",
  legacy_prepared: "Снимок уже подготовлен к переносу со старыми ссылками. Для него требуется завершить исходный сценарий.",
  bot_unavailable: "Сначала подключите бота PAUK, чтобы перенести связанные данные клиентов.",
};

function callMigration(input: { migration: string; plan: string; digest: string; actor: string; timezone: string }) {
  return new Promise<string>((resolve, reject) => {
    const socket = createConnection("/run/pauk-remnawave-native.sock");
    let response = "";
    socket.setEncoding("utf8");
    socket.setTimeout(17_000, () => socket.destroy(new Error("migration timeout")));
    socket.on("error", reject);
    socket.on("connect", () => socket.write(JSON.stringify(input) + "\n"));
    socket.on("data", (part: string) => {
      response += part;
      if (response.length > 256) socket.destroy(new Error("invalid migration response"));
    });
    socket.on("end", () => {
      try { resolve(JSON.parse(response).status); }
      catch (error) { reject(error); }
    });
  });
}

export async function activateRemnawaveAction(
  _previous: MigrationActionState,
  form: FormData,
): Promise<MigrationActionState> {
  const session = await requireSession();
  if (session.role !== "owner") return { status: "error", message: "Действие доступно владельцу PAUK." };
  const migration = form.get("migration");
  const plan = form.get("plan");
  const digest = form.get("digest");
  const timezone = form.get("timezone");
  if (typeof migration !== "string" || !uuid.test(migration) ||
      typeof plan !== "string" || !uuid.test(plan) ||
      typeof digest !== "string" || !digestPattern.test(digest) ||
      typeof timezone !== "string" || !/^[A-Za-z][A-Za-z0-9_+\/-]{0,63}$/.test(timezone) ||
      form.get("confirm") !== "yes") {
    return { status: "error", message: "Выберите группу и подтвердите условия переноса." };
  }

  try {
    const status = await callMigration({ migration, plan, digest, actor: session.accountID, timezone });
    if (status === "ok") {
      revalidatePath("/migrations/remnawave");
      revalidatePath("/migrations/remnawave/" + migration);
      revalidatePath("/clients");
    }
    return { status, message: messages[status] ?? "Панель не подтвердила перенос. Обновите страницу перед повтором." };
  } catch {
    return { status: "error", message: "Панель не получила результат. Обновите страницу перед повтором." };
  }
}
