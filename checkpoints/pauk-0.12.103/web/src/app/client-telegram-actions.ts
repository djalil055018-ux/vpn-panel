"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, linkVPNClientTelegram } from "@/lib/control-plane";

export type TelegramLinkState = { ok: boolean; message: string; telegramID?: string };

export async function linkClientTelegramAction(_previous: TelegramLinkState, data: FormData): Promise<TelegramLinkState> {
  const session = await requireSession();
  if (session.role === "monitor") return { ok: false, message: "Для привязки Telegram нужны права администратора." };
  const clientID = String(data.get("client_id") ?? "").trim();
  const telegramID = String(data.get("telegram_id") ?? "").trim();
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(clientID)) return { ok: false, message: "Клиент не найден. Обновите страницу." };
  if (!/^[1-9][0-9]{0,15}$/.test(telegramID) || BigInt(telegramID) > BigInt("9007199254740991")) return { ok: false, message: "Введите числовой Telegram ID пользователя, без @ и пробелов." };
  try {
    const result = await linkVPNClientTelegram(clientID, telegramID);
    revalidatePath("/clients");
    return { ok: true, message: result.changed ? "Telegram привязан к этой подписке. Клиент может открыть бота и обновить список подписок." : "Этот Telegram уже привязан к подписке.", telegramID: result.telegram_id };
  } catch (error) {
    if (error instanceof ControlPlaneError) {
      if (error.status === 409 && error.body.includes("another Telegram")) return { ok: false, message: "Подписка уже привязана к другому Telegram ID. Текущая привязка сохранена." };
      if (error.status === 409) return { ok: false, message: "Привязка недоступна: проверьте подключение бота и завершение переноса клиента." };
      if (error.status === 404) return { ok: false, message: "Клиент больше не доступен. Обновите страницу." };
      if (error.status === 403) return { ok: false, message: "Недостаточно прав для привязки Telegram." };
    }
    return { ok: false, message: "Не удалось подтвердить привязку. Обновите страницу перед повторной попыткой." };
  }
}
