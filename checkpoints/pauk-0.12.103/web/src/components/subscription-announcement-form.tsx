"use client";

import { useActionState, useState } from "react";
import { saveSubscriptionAnnouncementAction } from "@/app/subscription-announcement-actions";

export function SubscriptionAnnouncementForm({ initialText }: { initialText: string }) {
  const [text, setText] = useState(initialText);
  const [state, action, pending] = useActionState(saveSubscriptionAnnouncementAction, {
    ok: true, message: "",
  });
  const length = [...text.trim()].length;

  return (
    <form action={action} className="portal-form subscription-announcement-form">
      <label>
        Текст объявления
        <textarea
          name="announcement"
          rows={3}
          value={text}
          onChange={(event) => setText(event.target.value)}
          aria-describedby="announcement-help"
          disabled={pending}
        />
      </label>
      <p className="plan-muted" id="announcement-help">
        {length} / 200 символов. Клиенты увидят текст после обновления подписки в INCY. Пустое поле скрывает объявление.
      </p>
      <div>
        <button className="button primary" disabled={pending || length > 200}>
          {pending ? "Сохранение…" : "Сохранить объявление"}
        </button>
      </div>
      {state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}
    </form>
  );
}
