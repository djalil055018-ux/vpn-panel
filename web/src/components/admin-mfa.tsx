"use client";
import Link from "next/link";
import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { QRCodeSVG } from "qrcode.react";
import { ownMFAAction } from "@/app/admin-mfa-actions";
import type { AdminMFAStatus, MFAActionState } from "@/lib/admin-mfa-types";

const initial: MFAActionState = { ok: false, message: "" };
function Submit({ children }: { children: React.ReactNode }) {
  const { pending } = useFormStatus();
  return <button className="button primary" disabled={pending}>{pending ? "Проверка…" : children}</button>;
}
function Password() { return <label>Текущий пароль<input name="password" type="password" autoComplete="current-password" maxLength={1024} required /></label>; }
function Factor({ confirmation = false }: { confirmation?: boolean }) { return <label>{confirmation ? "Код приложения" : "Код приложения или резервный код"}<input name="factor" autoComplete="one-time-code" inputMode={confirmation ? "numeric" : "text"} pattern={confirmation ? "[0-9]{6}" : undefined} maxLength={confirmation ? 6 : 64} required /></label>; }

export function AdminMFA({ value }: { value: AdminMFAStatus | null }) {
  const [state, action] = useActionState(ownMFAAction, initial);
  if (!value) return <p className="plan-muted">Не удалось получить настройки двухфакторного входа. Обновите страницу позже.</p>;
  if (state.completed) return <div className="plan-form"><p role="status">{state.message}</p>{state.recovery_codes && <><p>Каждый код заменяет код приложения только один раз. Пароль всё равно потребуется. Храните коды отдельно от приложения.</p><div className="mfa-recovery-codes">{state.recovery_codes.map(code => <code key={code}>{code}</code>)}</div></>}<Link href="/account" className="button primary">Коды сохранены — продолжить</Link></div>;
  return <div className="plan-form">
    <p>После пароля потребуется одноразовый код из вашего приложения-аутентификатора.</p>
    <strong className={value.status.enabled ? "operations-good" : "plan-muted"}>{value.status.enabled ? "Двухфакторный вход включён" : "Двухфакторный вход выключен"}</strong>
    {state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}
    {state.enrollment ? <><div className="mfa-qr"><QRCodeSVG value={state.enrollment.provisioning_url} size={208} marginSize={4} aria-label="QR-код настройки аутентификатора" /></div><p>Для ручного добавления используйте этот ключ:</p><code className="mfa-setup-secret">{state.enrollment.secret}</code><p className="plan-muted">QR-код и ключ позволяют получать коды входа. Сохраните их только в своём приложении.</p><form action={action} className="plan-form"><input name="operation" type="hidden" value="confirm" /><Password /><Factor confirmation /><Submit>Подтвердить и получить резервные коды</Submit></form></> : !value.status.enabled ? value.configured ? <form action={action} className="plan-form"><input name="operation" type="hidden" value="enroll" /><Password /><Submit>Настроить двухфакторный вход</Submit></form> : <p>Настройка временно недоступна. Обратитесь к владельцу панели.</p> : <>
      <p>Осталось резервных кодов: {value.status.recovery_codes_remaining}.</p>
      <details><summary>Заменить резервные коды</summary><form action={action} className="plan-form"><input name="operation" type="hidden" value="recovery-codes" /><Password /><Factor /><p className="plan-muted">Прежние резервные коды перестанут действовать. Все сеансы будут завершены.</p><Submit>Получить новые коды</Submit></form></details>
      <details><summary>Отключить двухфакторный вход</summary><form action={action} className="plan-form"><input name="operation" type="hidden" value="disable" /><Password /><Factor /><p className="plan-muted">После отключения и нового входа будет достаточно пароля.</p><Submit>Отключить и завершить сеансы</Submit></form></details>
    </>}
  </div>;
}
