"use client";

import { useActionState, useEffect } from "react";
import { useFormStatus } from "react-dom";
import { useRouter } from "next/navigation";
import { linkClientTelegramAction } from "@/app/client-telegram-actions";

function Submit() {
  const { pending } = useFormStatus();
  return <button type="submit" className="button primary" disabled={pending}>{pending ? "Привязываем…" : "Привязать Telegram"}</button>;
}

export function ClientTelegram({ clientID, telegramID, canLink }: { clientID: string; telegramID?: string | null; canLink: boolean }) {
  const router = useRouter();
  const [state, action] = useActionState(linkClientTelegramAction, { ok: false, message: "" });
  useEffect(() => { if (state.ok) router.refresh(); }, [state.ok, router]);
  const linked = state.telegramID || telegramID;
  if (linked) return <div className="client-lifecycle"><p>Telegram ID: <strong>{linked}</strong></p><p className="plan-feedback" role="status">{state.message || "Telegram привязан к подписке."}</p></div>;
  if (!canLink) return <p className="plan-muted">Telegram пока не привязан.</p>;
  return <div className="client-lifecycle"><p className="plan-muted">Можно привязать существующую подписку, даже если клиент покупал её без Telegram.</p><form action={action}>
    <input type="hidden" name="client_id" value={clientID} />
    <label>Telegram ID пользователя<input name="telegram_id" type="text" inputMode="numeric" pattern="[1-9][0-9]{0,15}" maxLength={16} autoComplete="off" placeholder="Например, 8045917391" required /></label>
    <Submit />
    {state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}
  </form></div>;
}
