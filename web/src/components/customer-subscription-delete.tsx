"use client";

import { useId, useRef, useState } from "react";

export function CustomerSubscriptionDelete({ name, disabled, pending, onDelete }: {
  name: string; disabled: boolean; pending?: boolean; onDelete: () => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const title = useId();
  const description = useId();
  const [confirmed, setConfirmed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const busy = disabled || submitting;
  return <>
    <button type="button" className="customer-text-button customer-delete-trigger" disabled={busy} onClick={() => {
      setConfirmed(false); setError(""); dialog.current?.showModal(); cancel.current?.focus();
    }}>{pending ? "Завершить удаление →" : "Удалить подписку"}</button>
    <dialog ref={dialog} className="customer-delete-dialog" aria-labelledby={title} aria-describedby={description}
      onCancel={event => { if (submitting) event.preventDefault(); }}>
      <form onSubmit={async event => {
        event.preventDefault(); if (!confirmed || busy) return;
        setSubmitting(true); setError("");
        try { await onDelete(); dialog.current?.close(); }
        catch (failure) { setError(failure instanceof Error ? failure.message : "Не удалось удалить подписку. Повторите попытку."); }
        finally { setSubmitting(false); }
      }}>
        <span className="customer-delete-symbol" aria-hidden="true">×</span>
        <p className="subscription-kicker">УПРАВЛЕНИЕ ПОДПИСКОЙ</p>
        <h2 id={title}>Удалить подписку?</h2>
        <p className="customer-delete-name">{name}</p>
        <p id={description}>Подписка и VPN-доступ будут удалены. Подключённые устройства потеряют доступ. Отменить удаление в кабинете нельзя.</p>
        <p className="customer-delete-note">История платежей сохранится. Неиспользованные дни не переносятся на другие подписки.</p>
        <label className="customer-delete-confirm"><input type="checkbox" checked={confirmed} disabled={submitting}
          onChange={event => setConfirmed(event.target.checked)} required />
          <span>Я понимаю, что VPN-доступ по этой подписке будет удалён.</span>
        </label>
        {error && <p className="customer-delete-error" role="alert">{error}</p>}
        <div className="customer-delete-actions">
          <button ref={cancel} type="button" className="customer-button" disabled={submitting} onClick={() => dialog.current?.close()}>Отмена</button>
          <button type="submit" className="customer-button customer-delete-submit" disabled={!confirmed || busy}>{submitting ? "Удаляем…" : "Удалить подписку"}</button>
        </div>
      </form>
    </dialog>
  </>;
}
