"use client";

import { useActionState, useEffect, useId, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { requestNodeRebootAction, type NodeRebootActionState } from "@/app/node-reboot-actions";

const initialState: NodeRebootActionState = { ok: false, message: "" };

export function NodeReboot({ id, name, disabled = false, disabledReason }: { id: string; name: string; disabled?: boolean; disabledReason?: string }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const inputId = useId();
  const router = useRouter();
  const [state, action, pending] = useActionState(requestNodeRebootAction, initialState);
  const [confirmation, setConfirmation] = useState("");
  const [accepted, setAccepted] = useState(false);

  useEffect(() => {
    if (state.ok) {
      dialog.current?.close();
      router.refresh();
    }
  }, [router, state]);

  function openDialog() {
    setConfirmation("");
    setAccepted(false);
    dialog.current?.showModal();
  }

  return <>
    <button type="button" className="button danger node-reboot-trigger" onClick={openDialog} disabled={disabled} aria-label={`Перезагрузить сервер ${name}`} title={disabled ? (disabledReason ?? "Доступно только для сервера на связи с синхронизированными настройками") : undefined}>Перезагрузить</button>
    {state.message && <p className={`node-reboot-feedback${state.ok ? "" : " error"}`} role="status">{state.message}</p>}
    <dialog ref={dialog} className="node-reboot-dialog" aria-labelledby={`${inputId}-title`} aria-describedby={`${inputId}-warning`} onCancel={event => { if (pending) event.preventDefault(); }}>
      <form action={action} className="node-reboot-form">
        <h2 id={`${inputId}-title`}>Перезагрузить сервер «{name}»?</h2>
        <p id={`${inputId}-warning`}>Все VPN-подключения на сервере прервутся. Возврат в сеть обычно занимает несколько минут. Настройки и данные клиентов сохранятся.</p>
        <input type="hidden" name="node_id" value={id} />
        <label htmlFor={inputId}>Для подтверждения введите название сервера<input id={inputId} name="confirm_name" value={confirmation} onChange={event => setConfirmation(event.target.value)} autoComplete="off" maxLength={80} required disabled={pending} /></label>
        <label className="node-reboot-confirm"><input type="checkbox" name="confirm_reboot" value="yes" checked={accepted} onChange={event => setAccepted(event.target.checked)} required disabled={pending} />Понимаю, что VPN временно отключится</label>
        {state.message && !state.ok && <p className="node-reboot-feedback error" role="alert">{state.message}</p>}
        <div className="header-actions">
          <button type="button" className="button" onClick={() => dialog.current?.close()} disabled={pending}>Отмена</button>
          <button type="submit" className="button danger" disabled={pending || disabled || confirmation !== name || !accepted}>{pending ? "Отправка…" : "Подтвердить перезагрузку"}</button>
        </div>
      </form>
    </dialog>
  </>;
}
