"use client";

import { useActionState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { accessPlanAction } from "@/app/access-plan-actions";
import type { AccessPlanDetail } from "@/lib/control-plane";
import { BotPlanMembers } from "@/components/bot-plan-members";

type Option = { id: string; name: string };
function Submit({ children, danger = false }: { children: ReactNode; danger?: boolean }) {
  const { pending } = useFormStatus();
  return <button className={`button ${danger ? "danger" : "primary"}`} disabled={pending}>{pending ? "Сохранение…" : children}</button>;
}
function ActionForm({ tenant, plan, operation, children, compact = false }: { tenant: string; plan?: string; operation: string; children: ReactNode; compact?: boolean }) {
  const [state, action] = useActionState(accessPlanAction, { ok: false, message: "" });
  return <form action={action} className={compact ? "plan-form plan-form-compact" : "plan-form"}>
    <input type="hidden" name="tenant_id" value={tenant} /><input type="hidden" name="plan_id" value={plan ?? ""} />
    <input type="hidden" name="operation" value={operation} />{children}
    {state.message && <p className={state.ok ? "plan-feedback" : "plan-feedback error"} role="status">{state.message}</p>}
  </form>;
}
function PlanFields({ plan }: { plan?: AccessPlanDetail }) {
  return <>
    <label>Название<input name="name" required maxLength={200} defaultValue={plan?.name ?? ""} placeholder="Например, Европа" /></label>
    <label>Код группы<input name="code" required maxLength={64} pattern="[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}" defaultValue={plan?.code ?? ""} placeholder="europe" /></label>
    <label className="plan-check"><input type="checkbox" name="enabled" defaultChecked={plan?.enabled ?? true} /> Группа включена</label>
  </>;
}
function Membership({ tenant, plan, title, available, assigned, kind }: { tenant: string; plan: AccessPlanDetail; title: string; available: Option[]; assigned: string[]; kind: "service" | "client" }) {
  const remaining = available.filter(item => !assigned.includes(item.id));
  return <section className="plan-members"><h3>{title} <span className="plan-count">{assigned.length}</span></h3>
    {assigned.length === 0 && <p className="plan-muted">{kind === "service" ? "Сервисы пока не добавлены." : "Ручных назначений пока нет."}</p>}
    <ul>{assigned.map(id => <li key={id}><span>{available.find(item => item.id === id)?.name ?? "Недоступная запись"}</span>
      <ActionForm tenant={tenant} plan={plan.id} operation={`remove-${kind}`} compact><input type="hidden" name="target_id" value={id} /><Submit>Убрать</Submit></ActionForm>
    </li>)}</ul>
    {remaining.length > 0 && <ActionForm tenant={tenant} plan={plan.id} operation={kind === "service" ? "add-service" : "assign-client"} compact>
      <label className="plan-select-label">{kind === "service" ? "Добавить сервис" : "Назначить клиенту"}<select name="target_id" required defaultValue=""><option value="" disabled>Выберите {kind === "service" ? "сервис" : "клиента"}</option>{remaining.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <Submit>{kind === "service" ? "Добавить" : "Назначить"}</Submit>
    </ActionForm>}
  </section>;
}
export function AccessPlanManagement({ tenant, plans, services, clients }: { tenant: string; plans: AccessPlanDetail[]; services: Option[]; clients: Option[] }) {
  return <>
    <section className="panel"><div className="panel-header"><div><h2>Новая группа доступа</h2><p>Объедините сервисы и назначайте доступ одним действием.</p></div></div>
      <ActionForm tenant={tenant} operation="create"><PlanFields /><Submit>Создать группу</Submit></ActionForm>
    </section>
    {plans.length === 0 && <div className="panel empty">Групп доступа пока нет. Создайте первую группу выше.</div>}
    <div className="plan-grid">{plans.map(plan => <article className="panel" key={plan.id}>
      <div className="panel-header"><div><h2>{plan.name}</h2><p>{plan.code}</p></div><span className={`status ${plan.enabled ? "success" : "warning"}`}>{plan.enabled ? "Включён" : "Отключён"}</span></div>
      <details className="plan-settings"><summary>Настройки группы</summary>
        <ActionForm tenant={tenant} plan={plan.id} operation="update"><PlanFields plan={plan} /><Submit>Сохранить</Submit></ActionForm>
        <p className="plan-muted">Отключение группы снимет доступ через неё у всех назначенных клиентов. Другие группы и прямые назначения сохранятся.</p>
      </details>
      <Membership tenant={tenant} plan={plan} title="VPN-сервисы" available={services} assigned={plan.service_ids} kind="service" />
      <Membership tenant={tenant} plan={plan} title="Ручные назначения" available={clients} assigned={plan.client_ids} kind="client" />
      <BotPlanMembers assigned={plan.bot_client_ids} clients={clients} />
      <details className="plan-settings"><summary>Удаление группы</summary><p className="plan-muted">Группа и её назначения будут удалены. Клиенты и сервисы останутся.</p>
        <ActionForm tenant={tenant} plan={plan.id} operation="delete"><label className="plan-check"><input type="checkbox" name="confirm" value="yes" required /> Подтверждаю удаление «{plan.name}»</label><Submit danger>Удалить тариф</Submit></ActionForm>
      </details>
    </article>)}</div>
  </>;
}
