"use client";

import { useActionState, useEffect, useId, useRef } from "react";
import { useRouter } from "next/navigation";
import { renameNodeAction, type RenameNodeActionState } from "@/app/node-actions";

const initialState: RenameNodeActionState = { ok: false, message: "" };

export function NodeRename({ id, name }: { id: string; name: string }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const inputId = useId();
  const router = useRouter();
  const [state, action, pending] = useActionState(renameNodeAction, initialState);

  useEffect(() => {
    if (state.ok) {
      dialog.current?.close();
      router.refresh();
    }
  }, [router, state]);

  return <>
    <button type="button" className="button node-rename-trigger" onClick={() => dialog.current?.showModal()} aria-label={`Изменить название сервера ${name}`}>Переименовать</button>
    <dialog ref={dialog} className="node-rename-dialog" aria-labelledby={`${inputId}-title`} onCancel={event => { if (pending) event.preventDefault(); }}>
      <form action={action} className="node-rename-form">
        <h2 id={`${inputId}-title`}>Название сервера</h2>
        <p>Новое название появится в панели. Настройки VPN и подключения клиентов не изменятся.</p>
        <input type="hidden" name="node_id" value={id} />
        <label htmlFor={inputId}>Название<input id={inputId} name="name" defaultValue={name} autoComplete="off" maxLength={80} required disabled={pending} /></label>
        {state.message && <p className={`plan-feedback${state.ok ? "" : " error"}`} role="status">{state.message}</p>}
        <div className="header-actions">
          <button type="button" className="button" onClick={() => dialog.current?.close()} disabled={pending}>Отмена</button>
          <button type="submit" className="button primary" disabled={pending}>{pending ? "Сохранение…" : "Сохранить название"}</button>
        </div>
      </form>
    </dialog>
  </>;
}
