import Link from "next/link";
import { requireSession } from "@/lib/auth";
import { getMonitoringStatus, getOperationsStatus, getSubscriptionObservations } from "@/lib/control-plane";
import { incidentRules } from "@/lib/monitoring-values";
import { adminRoleLabels } from "@/lib/admin-types";
import { logoutAction } from "@/app/actions";
import { generationPresentation } from "@/lib/protocol-presentation";
export const dynamic = "force-dynamic";
export default async function MonitorPage() {
  const session = await requireSession();
  const [operations, incidents, observations] = await Promise.all([
    getOperationsStatus(), getMonitoringStatus(),
    session.role === "owner" ? getSubscriptionObservations().catch(() => null) : null,
  ]);
  const open = incidents.incidents.filter(item => !item.resolved_at);
  return <main className="content"><header className="page-header"><div><h1>Наблюдение за платформой</h1><p>{session.user} · {adminRoleLabels[session.role]}. Состояние на момент открытия страницы.</p></div><Link className="button ghost" href="/account">Мой аккаунт</Link></header>
    <section className="panel"><div className="panel-header"><div><h2>Ноды</h2><p>Связь, работоспособность и применение изменений.</p></div></div><div className="table-wrap"><table><thead><tr><th>Нода</th><th>Связь</th><th>Состояние</th><th>Изменения доступа</th></tr></thead><tbody>{operations.nodes.map(node => <tr key={node.id}><td>{node.name}</td><td>{node.lifecycle.online ? "В сети" : "Нет связи"}</td><td>{!node.lifecycle.health_fresh ? "Данные устарели" : node.lifecycle.healthy ? "Работает" : "Нужна проверка"}</td><td>{generationPresentation(node.lifecycle.desired_generation, node.lifecycle.applied_generation, node.lifecycle.registered).label}</td></tr>)}</tbody></table></div></section>
    <section className="panel"><div className="panel-header"><h2>Открытые инциденты: {incidents.open_count}</h2></div>{open.length === 0 ? <p className="plan-muted">Открытых инцидентов нет.</p> : <ul>{open.map(item => <li key={item.id}><strong>{incidentRules[item.rule]?.title ?? "Требуется проверка"}</strong> · {item.resource_name} · {item.severity === "critical" ? "Критический" : "Предупреждение"}</li>)}</ul>}<p className="plan-muted">Последняя проверка: {incidents.last_success_at ? new Date(incidents.last_success_at).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" }) : "нет данных"}.</p></section>
    <section className="panel"><div className="panel-header"><h2>Резервное копирование</h2></div><p className="plan-muted">Последняя проверенная копия: {operations.control_plane_backup?.last_verified_at ? new Date(operations.control_plane_backup.last_verified_at).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" }) : "нет данных"}.</p></section>
    {session.role === "owner" && <section className="panel">
      <div className="panel-header">
        <div><h2>Выдача подписок</h2><p>Запросы, дошедшие до панели за последние 60 минут. Счётчики хранятся в памяти и сбрасываются при перезапуске.</p></div>
        <Link className="button ghost" href="/monitor" prefetch={false}>Обновить</Link>
      </div>
      {!observations ? <p className="plan-muted">Данные временно недоступны.</p> : observations.rows.length === 0 ? (
        <p className="plan-muted">За этот период запросов нет.</p>
      ) : <>
        <div className="table-wrap"><table>
          <thead><tr><th>Приложение</th><th>Формат</th><th>HTTP</th><th>Запросов</th></tr></thead>
          <tbody>{observations.rows.map(row => <tr key={JSON.stringify([row.client, row.format, row.result])}>
            <td>{row.client}</td><td>{row.format}</td><td>{row.result}</td><td>{row.count}</td>
          </tr>)}</tbody>
        </table></div>
        <details><summary>Запросы по минутам</summary>
          <div className="table-wrap"><table>
            <thead><tr><th>Время (МСК)</th><th>Запросов</th></tr></thead>
            <tbody>{observations.timeline.slice().reverse().map(point => <tr key={point.minute}>
              <td>{new Date(point.minute).toLocaleTimeString("ru-RU", { timeZone: "Europe/Moscow", hour: "2-digit", minute: "2-digit" })}</td><td>{point.count}</td>
            </tr>)}</tbody>
          </table></div>
        </details>
      </>}
    </section>}
    <form action={logoutAction}><button className="button ghost">Выйти</button></form>
  </main>;
}
