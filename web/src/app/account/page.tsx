import Link from "next/link";
import { requireSession } from "@/lib/auth";
import { adminRoleLabels } from "@/lib/admin-types";
import { OwnPasswordForm } from "@/components/admin-account-forms";
import { logoutAction } from "@/app/actions";
import { getOwnAdminSessions } from "@/lib/control-plane";
import { getOwnMFAStatus } from "@/lib/control-plane";
import { AdminMFA } from "@/components/admin-mfa";
import { AdminSessions } from "@/components/admin-sessions";
export const dynamic = "force-dynamic";
export default async function AccountPage() {
  const session = await requireSession();
  const sessions = session.legacy ? null : await getOwnAdminSessions();
  const mfa = session.legacy ? null : await getOwnMFAStatus().catch(() => null);
  return <main className="content"><header className="page-header"><div><h1>Мой аккаунт</h1><p>{session.user} · {adminRoleLabels[session.role]}</p></div><Link className="button ghost" href={session.role === "monitor" ? "/monitor" : "/dashboard"}>Вернуться в панель</Link></header>{sessions && <AdminSessions sessions={sessions} />}{!session.legacy && <section className="panel"><div className="panel-header"><h2>Двухфакторный вход</h2></div><AdminMFA value={mfa} /></section>}<section className="panel"><div className="panel-header"><h2>Пароль для входа</h2></div>{session.legacy ? <p className="plan-muted">Выйдите и войдите снова, чтобы управлять паролем в новой системе аккаунтов.</p> : <OwnPasswordForm />}</section><form action={logoutAction}><button className="button ghost">Выйти</button></form></main>;
}
