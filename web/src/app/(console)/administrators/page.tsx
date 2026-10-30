import { redirect } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { getAdminAccounts } from "@/lib/control-plane";
import { adminRoleLabels } from "@/lib/admin-types";
import { CreateAdminForm, EditAdminForm, ResetAdminPasswordForm } from "@/components/admin-account-forms";
export const dynamic = "force-dynamic";
export default async function AdministratorsPage() {
  const session = await requireSession();
  if (session.role !== "owner") redirect(session.role === "monitor" ? "/monitor" : "/dashboard");
  const accounts = await getAdminAccounts();
  return <><header className="page-header"><div><h1>Администраторы</h1><p>Персональный доступ к панели и ответственность за изменения.</p></div></header>
    <section className="panel"><div className="panel-header"><div><h2>Создать аккаунт</h2><p>Владелец управляет аккаунтами. Администратор управляет платформой. Наблюдатель видит только состояние нод и инциденты.</p></div></div><CreateAdminForm /></section>
    {accounts.map(account => <section className="panel" key={`${account.id}:${account.security_version}`}><div className="panel-header"><div><h2>{account.username}{account.id === session.accountID ? " · это вы" : ""}</h2><p>{adminRoleLabels[account.role]} · {account.enabled ? "Вход разрешён" : "Отключён"}</p></div></div><EditAdminForm account={account} /><details><summary>Задать новый пароль</summary><ResetAdminPasswordForm id={account.id} /></details></section>)}
    <p className="plan-muted">Изменение роли, отключение и смена пароля завершают активные сеансы. Последнего активного владельца нельзя отключить или лишить роли владельца.</p>
  </>;
}
