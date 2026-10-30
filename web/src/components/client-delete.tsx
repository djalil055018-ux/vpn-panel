"use client";

import { useActionState, useId, useState } from "react";
import { useFormStatus } from "react-dom";
import { deleteVPNClientAction } from "@/app/client-delete-actions";

function DeleteSubmit({ matches }: { matches: boolean }) {
  const { pending } = useFormStatus();
  return <button type="submit" className="button danger" disabled={pending || !matches}>{pending ? "Удаление…" : "Удалить навсегда"}</button>;
}

export function ClientDelete({ id, name, imported = false, audience = "console" }: { id: string; name: string; imported?: boolean; audience?: "console" | "portal" }) {
  const [state, action] = useActionState(deleteVPNClientAction, { ok: false, message: "" });
  const [confirmation, setConfirmation] = useState("");
  const hintId = useId();
  return <details className="client-lifecycle client-delete">
    <summary>Удалить клиента</summary>
    <form action={action}>
      <input type="hidden" name="client_id" value={id} />
      <input type="hidden" name="audience" value={audience} />
      <p id={hintId}>Будут удалены учётная запись «{name}», подписка и VPN-ключи. Отмена невозможна. Отзыв доступа завершится после применения конфигурации на нодах.</p>
      <p className="plan-muted">Оплаченные счета сохранятся, неоплаченные будут аннулированы.{imported && " Исходная панель Remnawave и сохранённый снимок останутся без изменений; повторный импорт не восстановит клиента."}</p>
      <label>Введите имя клиента<input name="confirm_name" value={confirmation} onChange={event => setConfirmation(event.target.value)} aria-describedby={hintId} autoComplete="off" maxLength={2048} required /></label>
      <DeleteSubmit matches={confirmation === name} />
      {state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}
    </form>
  </details>;
}
