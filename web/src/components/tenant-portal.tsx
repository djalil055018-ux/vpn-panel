"use client";

import { trafficQuota } from "@/lib/usage-policy";

import { useActionState, useState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { portalAction } from "@/app/portal/actions";
import { ClientDelete } from "@/components/client-delete";
import { BotPlanMembers } from "@/components/bot-plan-members";
import { ClientConnection } from "@/components/client-connection";
import type { PortalClient, PortalClientUsage, PortalPlan, PortalService } from "@/lib/portal-api";

function Submit({ children, danger = false }: { children: ReactNode; danger?: boolean }) { const { pending } = useFormStatus(); return <button className={`button ${danger ? "danger" : "primary"}`} disabled={pending}>{pending ? "Сохранение…" : children}</button>; }
function Form({ operation, id = "", children }: { operation: string; id?: string; children: ReactNode }) {
  const [state, action] = useActionState(portalAction, { ok: false, message: "" });
  return <form action={action} className="portal-form"><input type="hidden" name="operation" value={operation} /><input type="hidden" name="id" value={id} />{children}{state.message && <p role="status" className={state.ok ? "plan-feedback" : "plan-feedback error"}>{state.message}</p>}</form>;
}
function when(value: string | null) { return value ? new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Moscow" }).format(new Date(value)) : "Бессрочно"; }
function inputDate(value: string | null) { return value ? new Date(Date.parse(value) + 3 * 3600000).toISOString().slice(0, 10) : ""; }
function usageBytes(value: number) { if (value < 1024) return `${value} Б`; const units = ["КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ"]; let amount = value / 1024, unit = units[0]; for (let index = 1; index < units.length && amount >= 1024; index += 1) { amount /= 1024; unit = units[index]; } return `${amount >= 10 ? amount.toFixed(1) : amount.toFixed(2)} ${unit}`; }
function SubscriptionButtons() { const { pending } = useFormStatus(); return <div className="credential-buttons"><button className="button primary" name="operation" value="subscription" disabled={pending}>{pending ? "Проверка…" : "Получить подписку"}</button><button className="button ghost" name="operation" value="rotate-subscription" disabled={pending}>Заменить ссылку</button></div>; }
function Subscription({ id }: { id: string }) {
  const [state, action] = useActionState(portalAction, { ok: false, message: "" });
  const [show, setShow] = useState(false), [copied, setCopied] = useState(false);
  return <details className="portal-details"><summary>Подписка клиента</summary><form action={action} className="portal-form"><input type="hidden" name="id" value={id} /><SubscriptionButtons /><p className="plan-muted">Замена ссылки отключает прежнюю ссылку подписки.</p>{state.message && <p role="status">{state.message}</p>}{state.subscription && <><label>Ссылка подписки<input type={show ? "text" : "password"} value={state.subscription} readOnly autoComplete="off" /></label><div className="credential-buttons"><button type="button" className="button ghost" onClick={() => setShow(!show)}>{show ? "Скрыть" : "Показать"}</button><button type="button" className="button primary" onClick={async () => { try { await navigator.clipboard.writeText(state.subscription!); setCopied(true); } catch { setShow(true); } }}>{copied ? "Скопировано" : "Копировать ссылку"}</button></div></>}</form></details>;
}
function PlanFields({ plan }: { plan?: PortalPlan }) { return <><label>Название тарифа<input name="name" defaultValue={plan?.name ?? ""} required maxLength={200} /></label><label>Код<input name="code" defaultValue={plan?.code ?? ""} required maxLength={64} pattern="[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}" placeholder="europe" /></label><label className="plan-check"><input type="checkbox" name="enabled" value="yes" defaultChecked={plan?.enabled ?? true} /> Тариф включён</label></>; }
function Membership({ plan, kind, options, operator }: { plan: PortalPlan; kind: "service" | "client"; options: { id: string; name: string }[]; operator: boolean }) {
  const ids = kind === "service" ? plan.service_ids : plan.client_ids, available = options.filter(option => !ids.includes(option.id));
  return <section className="portal-members"><h3>{kind === "service" ? "Сервисы" : "Ручные назначения"} · {ids.length}</h3>{ids.length === 0 && <p className="plan-muted">Пока нет.</p>}<ul>{ids.map(id => <li key={id}><span>{options.find(option => option.id === id)?.name ?? "Недоступная запись"}</span>{operator && <Form operation={`remove-${kind}`} id={plan.id}><input type="hidden" name="target" value={id} /><Submit>Убрать</Submit></Form>}</li>)}</ul>{operator && available.length > 0 && <Form operation={`add-${kind}`} id={plan.id}><label>{kind === "service" ? "Добавить сервис" : "Назначить клиенту"}<select name="target" required defaultValue=""><option value="" disabled>Выберите</option>{available.map(option => <option key={option.id} value={option.id}>{option.name}</option>)}</select></label><Submit>{kind === "service" ? "Добавить" : "Назначить"}</Submit></Form>}</section>;
}
function PortalUsage({ id, usage, operator }: { id: string; usage: PortalClientUsage; operator: boolean }) {
  const quota = trafficQuota(usage);
  if (!quota) return <p className="plan-muted">Политика трафика временно недоступна</p>;
  return <div className="client-usage">
    <strong>{usageBytes(usage.used_bytes)}{quota.limit > 0 ? ` из ${usageBytes(quota.limit)}` : " · без лимита"}</strong>
    <span>{quota.continuous ? "Без автоматического сброса" : "За текущий месяц"}</span>
    {quota.continuous && (usage.imported_bytes ?? 0) > 0 && <small>Включая {usageBytes(usage.imported_bytes!)} из предыдущей панели</small>}
    <span>{usage.active_ips === null ? "Количество активных адресов недоступно" : `${usage.active_ips} активных адресов`}{usage.device_limit ? ` · порог ${usage.device_limit}` : ""}</span>
    {usage.device_warning && <small className="operations-warning">Превышен заданный порог</small>}
    {operator && <details><summary>Лимиты трафика</summary>
      <Form operation={quota.continuous ? "client-continuous-limit" : "client-limits"} id={id}>
        <label>{quota.continuous ? "Общий лимит трафика, ГиБ" : "Трафик в месяц, ГиБ"}<input name={quota.continuous ? "limit_gib" : "monthly_gib"} type="number" min={0} max={9000000000000000 / 1073741824} step="any" required defaultValue={quota.limit / 1073741824} /></label>
        {!quota.continuous && <label>Порог активных адресов<input name="device_limit" type="number" min={0} max={1000} required defaultValue={usage.device_limit} /></label>}
        <p className="plan-muted">{quota.continuous ? "Изменение лимита сохраняет использованный трафик. Ноль снимает ограничение." : "Ноль снимает ограничение. Адреса показывают подключения приблизительно."}</p>
        <Submit>Сохранить лимиты</Submit>
      </Form>
    </details>}
  </div>;
}
export function TenantPortal({ clients, usages, plans, services, operator, connectionRevision }: { clients: PortalClient[]; usages: PortalClientUsage[]; plans: PortalPlan[]; services: PortalService[]; operator: boolean; connectionRevision: string }) {
  return <>
    <section id="clients"><div className="portal-section-heading"><h2>Клиенты</h2><span>{clients.length}</span></div>
      {operator && <details className="panel portal-create"><summary>Добавить клиента</summary><Form operation="create-client"><label>Имя клиента<input name="name" required maxLength={100} /></label><Submit>Создать клиента</Submit><p className="plan-muted">Новый клиент создаётся без назначенных тарифов. Срок можно установить в его настройках.</p></Form></details>}
      <div className="portal-grid">{clients.map(client => { const usage = usages.find(item => item.client_id === client.id); return <article className="panel portal-card" key={client.id}><header><h3>{client.name}</h3><span className={client.effective_status === "active" ? "operations-good" : "operations-warning"}>{client.remnawave_hold ? "Перенос не завершён" : client.effective_status === "active" ? "Активен" : client.effective_status === "expired" ? "Срок истёк" : client.effective_status === "quota_exceeded" ? "Лимит исчерпан" : "Отключён"}</span></header><p>Доступ: {when(client.expires_at)}</p>{client.remnawave_hold && <p className="plan-muted">Исходные подписки, трафик и ограничения сохранены в снимке. Переключение ещё не выполнено.</p>}{usage && !client.remnawave_hold && <PortalUsage id={client.id} usage={usage} operator={operator} />}{operator && !client.remnawave_hold && <><details className="portal-details"><summary>Настройки доступа</summary><Form operation={client.status === "disabled" ? "enable-client" : "disable-client"} id={client.id}><Submit>{client.status === "disabled" ? "Включить клиента" : "Отключить клиента"}</Submit></Form><Form operation="client-expiry" id={client.id}><label>Действует до (Москва)<input name="date" type="date" defaultValue={inputDate(client.expires_at)} /></label><label className="plan-check"><input name="unlimited" type="checkbox" value="yes" /> Сделать бессрочным</label><Submit>Сохранить срок</Submit><p className="plan-muted">Включение не продлевает истёкший срок.</p></Form></details><Subscription id={client.id} /><details className="portal-details"><summary>Ссылки, QR-коды и VPN-профили</summary><ClientConnection key={`${client.id}-${connectionRevision}`} clientID={client.id} audience="portal" /></details><ClientDelete id={client.id} name={client.name} audience="portal" /></>}</article>; })}</div>{clients.length === 0 && <p className="portal-empty">Клиентов пока нет.</p>}
    </section>
    <section id="plans"><div className="portal-section-heading"><h2>Тарифы доступа</h2><span>{plans.length}</span></div>
      {operator && <details className="panel portal-create"><summary>Создать тариф</summary><Form operation="create-plan"><PlanFields /><Submit>Создать тариф</Submit></Form></details>}
      <div className="portal-grid">{plans.map(plan => <article className="panel portal-card" key={plan.id}><header><h3>{plan.name}</h3><span className={plan.enabled ? "operations-good" : "plan-muted"}>{plan.enabled ? "Включён" : "Отключён"}</span></header><p className="plan-muted">{plan.code}</p>{operator && <details className="portal-details"><summary>Настройки тарифа</summary><Form operation="update-plan" id={plan.id}><PlanFields plan={plan} /><Submit>Сохранить тариф</Submit></Form><Form operation="delete-plan" id={plan.id}><label className="plan-check"><input name="confirm" type="checkbox" value="yes" required /> Удалить тариф и его назначения</label><Submit danger>Удалить тариф</Submit></Form></details>}<Membership plan={plan} kind="service" options={services} operator={operator} /><Membership plan={plan} kind="client" options={clients} operator={operator} /><BotPlanMembers assigned={plan.bot_client_ids} clients={clients} className="portal-members" /></article>)}</div>{plans.length === 0 && <p className="portal-empty">Тарифов пока нет.</p>}
    </section>
  </>;
}
