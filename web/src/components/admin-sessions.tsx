"use client";
import { useActionState } from "react";
import { revokeSessionAction } from "@/app/admin-session-actions";
import type { AdminSessionInfo } from "@/lib/admin-types";
function Revoke({ session }: { session?: AdminSessionInfo }) {
  const [state, action, pending] = useActionState(revokeSessionAction, { ok: false, message: "" });
  return <form action={action}><input type="hidden" name="scope" value={session ? "one" : "all"} />{session && <input type="hidden" name="session_id" value={session.id} />}<button className="button ghost" disabled={pending}>{pending ? "Завершение…" : session ? session.current ? "Выйти здесь" : "Завершить" : "Выйти из всех сеансов"}</button>{state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}</form>;
}
const when = (value: string) => new Date(value).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" });
export function AdminSessions({ sessions }: { sessions: AdminSessionInfo[] }) {
  return <section className="panel"><div className="panel-header"><div><h2>Сеансы входа</h2><p>Время указано по Москве. Сеанс действует до выхода, отзыва или окончания срока.</p></div></div><div className="table-wrap"><table><thead><tr><th>Вход</th><th>Действует до</th><th>Сеанс</th><th>Действие</th></tr></thead><tbody>{sessions.map(session => <tr key={session.id}><td>{when(session.created_at)}</td><td>{when(session.expires_at)}</td><td>{session.current ? "Текущий" : "Другой сеанс"}</td><td><Revoke session={session} /></td></tr>)}</tbody></table></div><div className="operations-content"><p className="plan-muted">Если вы не узнаёте время входа, завершите все сеансы и смените пароль. Выход из всех сеансов завершит и этот сеанс.</p><Revoke /></div></section>;
}
