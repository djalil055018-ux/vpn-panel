"use client";
import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { portalLoginAction } from "@/app/portal/actions";
function Submit() { const { pending } = useFormStatus(); return <button className="button primary" disabled={pending}>{pending ? "Проверка…" : "Войти в кабинет"}</button>; }
export function PortalLogin() { const [state, action] = useActionState(portalLoginAction, { ok: false, message: "" }); return <form action={action} className="portal-form"><label>Ключ доступа<input name="credential" type="password" required minLength={48} maxLength={48} autoComplete="off" spellCheck={false} /></label><Submit />{state.message && <p className="plan-feedback error" role="status">{state.message}</p>}</form>; }
