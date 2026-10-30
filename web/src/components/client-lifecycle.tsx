"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { clientLifecycleAction } from "@/app/client-lifecycle-actions";
function Submit({ label }: { label: string }) { const { pending } = useFormStatus(); return <button className="button ghost" disabled={pending}>{pending ? "Сохранение…" : label}</button>; }
function localDate(value?: string | null) { return value ? new Date(Date.parse(value) + 3 * 3600000).toISOString().slice(0, 10) : ""; }
export function ClientLifecycle({ id, name, status, expiresAt }: { id: string; name: string; status: string; expiresAt?: string | null }) {
  const [rename, renameAction] = useActionState(clientLifecycleAction, { ok: false, message: "" });
  const [toggle, toggleAction] = useActionState(clientLifecycleAction, { ok: false, message: "" });
  const [expiry, expiryAction] = useActionState(clientLifecycleAction, { ok: false, message: "" });
  return <details className="client-lifecycle"><summary>Изменить доступ</summary><form action={renameAction}><input type="hidden" name="client_id" value={id} /><input type="hidden" name="operation" value="rename" /><label>Имя клиента<input name="name" defaultValue={name} autoComplete="off" maxLength={100} required /></label><Submit label="Сохранить имя" />{rename.message && <p role="status" className={rename.ok ? "plan-feedback" : "plan-feedback error"}>{rename.message}</p>}</form><form action={toggleAction}><input type="hidden" name="client_id" value={id} /><input type="hidden" name="operation" value={status === "disabled" ? "enable" : "disable"} /><Submit label={status === "disabled" ? "Включить клиента" : "Отключить клиента"} />{toggle.message && <p role="status" className={toggle.ok ? "plan-feedback" : "plan-feedback error"}>{toggle.message}</p>}</form><form action={expiryAction}><input type="hidden" name="client_id" value={id} /><input type="hidden" name="operation" value="expiry" /><label>Действует до (Москва)<input name="date" type="date" defaultValue={localDate(expiresAt)} /></label><label className="plan-check"><input name="unlimited" type="checkbox" value="yes" /> Сделать бессрочным</label><Submit label="Сохранить срок" />{expiry.message && <p role="status" className={expiry.ok ? "plan-feedback" : "plan-feedback error"}>{expiry.message}</p>}</form></details>;
}
