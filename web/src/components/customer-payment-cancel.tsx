"use client";

import { useId, useRef, useState } from "react";

export function CustomerPaymentCancel({ title, disabled, onCancel }: {
  title: string; disabled: boolean; onCancel: () => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const back = useRef<HTMLButtonElement>(null);
  const heading = useId();
  const description = useId();
  const [unpaid, setUnpaid] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const busy = disabled || submitting;
  return <>
    <button type="button" className="customer-text-button" disabled={busy} onClick={() => {
      setUnpaid(false); setError(""); dialog.current?.showModal(); back.current?.focus();
    }}>Отменить заказ</button>
    <dialog ref={dialog} className="customer-delete-dialog" aria-labelledby={heading} aria-describedby={description}
      onCancel={event => { if (submitting) event.preventDefault(); }}>
      <form onSubmit={async event => {
        event.preventDefault(); if (!unpaid || busy) return;
        setSubmitting(true); setError("");
        try { await onCancel(); dialog.current?.close(); }
        catch (failure) { setError(failure instanceof Error ? failure.message : "Не удалось отменить заказ. Проверьте его статус."); }
        finally { setSubmitting(false); }
      }}>
        <span className="customer-delete-symbol" aria-hidden="true">×</span>
        <p className="subscription-kicker">УПРАВЛЕНИЕ ЗАКАЗОМ</p>
        <h2 id={heading}>Отменить неоплаченный заказ?</h2>
        <p className="customer-delete-name">{title}</p>
        <p id={description}>Заказ закроется. Подписка, оставшиеся дни и лимит устройств не изменятся. История заказа сохранится.</p>
        <p className="customer-delete-note">Если деньги уже списались, обратитесь в поддержку вместо отмены. Повторно платить не нужно.</p>
        <label className="customer-delete-confirm"><input type="checkbox" checked={unpaid} disabled={submitting} required
          onChange={event => setUnpaid(event.target.checked)} /><span>Я не оплачивал этот заказ.</span></label>
        {error && <p className="customer-delete-error" role="alert">{error}</p>}
        <div className="customer-delete-actions">
          <button ref={back} type="button" className="customer-button" disabled={submitting} onClick={() => dialog.current?.close()}>Назад</button>
          <button type="submit" className="customer-button customer-delete-submit" disabled={!unpaid || busy}>{submitting ? "Отменяем…" : "Отменить заказ"}</button>
        </div>
      </form>
    </dialog>
  </>;
}
