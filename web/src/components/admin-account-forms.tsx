"use client";
import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { adminAccountAction, ownPasswordAction } from "@/app/admin-account-actions";
import { adminRoleLabels, type AdminAccount } from "@/lib/admin-types";

const initial = { ok: false, message: "" };
function Submit({ children }: { children: React.ReactNode }) { const { pending } = useFormStatus(); return <button className="button primary" disabled={pending}>{pending ? "Сохранение…" : children}</button>; }
function Roles({ value = "monitor" }: { value?: string }) { return <label>Роль<select name="role" defaultValue={value}>{Object.entries(adminRoleLabels).map(([role, label]) => <option key={role} value={role}>{label}</option>)}</select></label>; }
function Password({ name = "password", label = "Пароль" }: { name?: string; label?: string }) { return <label>{label}<input name={name} type="password" autoComplete="new-password" minLength={15} maxLength={1024} required /></label>; }
function Feedback({ state }: { state: typeof initial }) { return state.message ? <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p> : null; }

export function CreateAdminForm() {
  const [state, action] = useActionState(adminAccountAction, initial);
  return <form action={action} className="plan-form"><input type="hidden" name="operation" value="create" /><label>Имя для входа<input name="username" autoComplete="off" pattern="[A-Za-z0-9][A-Za-z0-9._\-]*" maxLength={64} required /></label><p className="plan-muted">Латинские буквы, цифры, точка, дефис и подчёркивание. Первый символ — буква или цифра.</p><Roles /><Password /><p className="plan-muted">Не менее 15 символов. Передайте пароль сотруднику по доверенному каналу.</p><Submit>Создать аккаунт</Submit><Feedback state={state} /></form>;
}
export function EditAdminForm({ account }: { account: AdminAccount }) {
  const [state, action] = useActionState(adminAccountAction, initial);
  return <form action={action} className="plan-form"><input type="hidden" name="operation" value="update" /><input type="hidden" name="id" value={account.id} /><Roles value={account.role} /><label><input name="enabled" type="checkbox" defaultChecked={account.enabled} /> Вход разрешён</label><Submit>Сохранить доступ</Submit><Feedback state={state} /></form>;
}
export function ResetAdminPasswordForm({ id }: { id: string }) {
  const [state, action] = useActionState(adminAccountAction, initial);
  return <form action={action} className="plan-form"><input type="hidden" name="operation" value="password" /><input type="hidden" name="id" value={id} /><Password label="Новый пароль" /><Submit>Сменить пароль и завершить сеансы</Submit><Feedback state={state} /></form>;
}
export function OwnPasswordForm() {
  const [state, action] = useActionState(ownPasswordAction, initial);
  return <form action={action} className="plan-form"><label>Текущий пароль<input name="current_password" type="password" autoComplete="current-password" maxLength={1024} required /></label><Password name="new_password" label="Новый пароль" /><Password name="repeat_password" label="Повтор нового пароля" /><p className="plan-muted">Не менее 15 символов. После изменения потребуется войти снова на всех устройствах.</p><Submit>Изменить пароль</Submit><Feedback state={state} /></form>;
}
