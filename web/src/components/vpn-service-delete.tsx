"use client";

import { useActionState, useEffect, useState } from "react";
import { useFormStatus } from "react-dom";
import { useRouter } from "next/navigation";
import { deleteVPNServiceAction } from "@/app/vpn-service-actions";

function DeleteButton({ disabled }: { disabled: boolean }) {
  const { pending } = useFormStatus();
  return <button className="button danger" type="submit" disabled={disabled || pending}>{pending ? "Удаляем…" : "Удалить протокол"}</button>;
}

export function VPNServiceDelete({ serviceID, name }: { serviceID: string; name: string }) {
  const router = useRouter();
  const [state, action] = useActionState(deleteVPNServiceAction, { ok: false, message: "" });
  const [confirmation, setConfirmation] = useState("");
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    if (state.ok) router.refresh();
  }, [router, state.ok]);

  return <details className="plan-settings protocol-delete">
    <summary>Удалить протокол</summary>
    <p className="plan-muted">Конфигурация и привязка к тарифам и подпискам будут удалены. Узел получит новую конфигурацию; клиенты потеряют этот профиль после обновления подписки. Если протокол используется в каскаде или импортированной подписке, сначала удалите эту зависимость.</p>
    <form className="plan-form" action={action}>
      <input type="hidden" name="service_id" value={serviceID} />
      <label>Введите точное название конфигурации<input name="confirm_name" value={confirmation} onChange={event => setConfirmation(event.target.value)} maxLength={200} autoComplete="off" required /></label>
      <label className="plan-check"><input type="checkbox" name="confirm_delete" value="yes" checked={checked} onChange={event => setChecked(event.target.checked)} required /> Я понимаю, что профиль будет удалён у клиентов</label>
      {state.message && <p className={`plan-feedback${state.ok ? "" : " error"}`} role="status">{state.message}</p>}
      <DeleteButton disabled={confirmation !== name || !checked} />
    </form>
  </details>;
}
