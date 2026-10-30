import Link from "next/link";
import { requireSession } from "@/lib/auth";
import { getMonitoringStatus, getOperationsStatus } from "@/lib/control-plane";
import { incidentRules } from "@/lib/monitoring-values";
import { adminRoleLabels } from "@/lib/admin-types";
import { logoutAction } from "@/app/actions";
import { generationPresentation } from "@/lib/protocol-presentation";
export const dynamic = "force-dynamic";
export default async function MonitorPage() {
  const session = await requireSession();
  const [operations, incidents] = await Promise.all([getOperationsStatus(), getMonitoringStatus()]);
  const open = incidents.incidents.filter(item => !item.resolved_at);
  return <main className="content"><header className="page-header"><div><h1>Наблюдение за платформой</h1><p>{session.user} · {adminRoleLabels[session.role]}. Состояние на момент открытия страницы.</p></div><Link className="button ghost" href="/account">Мой аккаунт</Link></header>
    <section className="panel"><div className="panel-header"><div><h2>Ноды</h2><p>Связь, работоспособность и применение изменений.</p></div></div><div className="table-wrap"><table><thead><tr><th>Нода</th><th>Связь</th><th>Состояние</th><th>Изменения доступа</th></tr></thead><tbody>{operations.nodes.map(node => <tr key={node.id}><td>{node.name}</td><td>{node.lifecycle.online ? "В сети" : "Нет связи"}</td><td>{!node.lifecycle.health_fresh ? "Данные устарели" : node.lifecycle.healthy ? "Работает" : "Нужна проверка"}</td><td>{generationPresentation(node.lifecycle.desired_generation, node.lifecycle.applied_generation, node.lifecycle.registered).label}</td></tr>)}</tbody></table></div></section>
    <section className="panel"><div className="panel-header"><h2>Открытые инциденты: {incidents.open_count}</h2></div>{open.length === 0 ? <p className="plan-muted">Открытых инцидентов нет.</p> : <ul>{open.map(item => <li key={item.id}><strong>{incidentRules[item.rule]?.title ?? "Требуется проверка"}</strong> · {item.resource_name} · {item.severity === "critical" ? "Критический" : "Предупреждение"}</li>)}</ul>}<p className="plan-muted">Последняя проверка: {incidents.last_success_at ? new Date(incidents.last_success_at).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" }) : "нет данных"}.</p></section>
    <section className="panel"><div className="panel-header"><h2>Резервное копирование</h2></div><p className="plan-muted">Последняя проверенная копия: {operations.control_plane_backup?.last_verified_at ? new Date(operations.control_plane_backup.last_verified_at).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" }) : "нет данных"}.</p></section>
    <form action={logoutAction}><button className="button ghost">Выйти</button></form>
  </main>;
}
