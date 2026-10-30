"use client";

import { useActionState, useEffect, useId, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { deleteNodeAction } from "@/app/node-delete-actions";

export function NodeDelete({ id, name, online, decommissioning, desiredGeneration, appliedGeneration }: { id: string; name: string; online: boolean; decommissioning: boolean; desiredGeneration: number; appliedGeneration: number }) {
  const router = useRouter();
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId(), hintId = useId();
  const [confirmation, setConfirmation] = useState("");
  const [stopped, setStopped] = useState(false);
  const [state, action, pending] = useActionState(deleteNodeAction, { message: "" as string, decommissioning: false });
  const drained = decommissioning && (!online || (desiredGeneration > 0 && desiredGeneration === appliedGeneration));
  useEffect(() => { if (state.decommissioning) router.refresh(); }, [router, state.decommissioning]);
  return <>
    <button type="button" className="button danger" onClick={() => dialog.current?.showModal()} aria-label={`Удалить ноду ${name}`}>Удалить</button>
    <dialog ref={dialog} className="node-delete-dialog" aria-labelledby={titleId} aria-describedby={hintId} onCancel={event => { if (pending) event.preventDefault(); }}>
      <form action={action} className="node-delete-form">
        <h2 id={titleId}>Удалить ноду «{name}»?</h2>
        <p id={hintId}>Клиенты и история сохранятся. После финального удаления отзовём доступ агента; вернуть запись ноды в работу нельзя.</p>
        {online ? <p>Сервер сейчас на связи. Сначала PAUK отключит все его VPN-протоколы и дождётся применения пустой конфигурации. Агент может оставаться включённым; новые профили клиентов с этого узла исчезнут.</p> : <p>Сервер не отвечает. Перед удалением подтвердите, что на нём остановлены VPN-службы.</p>}
        <input type="hidden" name="node_id" value={id} />
        <label>Введите имя ноды<input name="confirm_name" value={confirmation} onChange={event => setConfirmation(event.target.value)} autoComplete="off" maxLength={2048} required disabled={pending} /></label>
        {online ? <input type="hidden" name="decommission_online" value="yes" /> : <label className="node-delete-confirm"><input type="checkbox" name="server_stopped" value="yes" checked={stopped} onChange={event => setStopped(event.target.checked)} required disabled={pending} /> VPN-службы на сервере остановлены</label>}
        {decommissioning && <p className="plan-muted">Применение generation {desiredGeneration}: {appliedGeneration}/{desiredGeneration}. {drained ? "Можно завершить удаление." : "Когда агент применит поколение, обновите состояние."}</p>}
        {state.message && <p className="plan-feedback error" role="status">{state.message}</p>}
        <div className="header-actions">
          <button type="button" className="button" onClick={() => dialog.current?.close()} disabled={pending}>Отмена</button>
          {decommissioning && !drained && <button type="button" className="button" onClick={() => router.refresh()} disabled={pending}>Обновить состояние</button>}
          <button type="submit" className="button danger" disabled={pending || confirmation !== name || (!online && !stopped) || (decommissioning && !drained)}>{pending ? "Проверяем…" : decommissioning ? "Завершить удаление" : online ? "Отключить VPN и продолжить" : "Удалить ноду"}</button>
        </div>
      </form>
    </dialog>
  </>;
}
