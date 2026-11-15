"use server";

import { requireSession } from "@/lib/auth";
import { saveSubscriptionAnnouncement } from "@/lib/subscription-announcement";

export type AnnouncementState = { ok: boolean; message: string };

export async function saveSubscriptionAnnouncementAction(
  _previous: AnnouncementState,
  form: FormData,
): Promise<AnnouncementState> {
  if ((await requireSession()).role !== "owner") {
    return { ok: false, message: "Настройка доступна владельцу панели." };
  }

  const value = form.get("announcement");
  if (typeof value !== "string") {
    return { ok: false, message: "Введите текст объявления." };
  }

  const text = value.replace(/\r\n?/g, "\n").trim();
  if ([...text].length > 200) {
    return { ok: false, message: "Сократите объявление до 200 символов." };
  }

  try {
    await saveSubscriptionAnnouncement(text);
    return {
      ok: true,
      message: text ? "Объявление сохранено." : "Объявление отключено.",
    };
  } catch {
    return { ok: false, message: "Не удалось сохранить объявление. Повторите позже." };
  }
}
