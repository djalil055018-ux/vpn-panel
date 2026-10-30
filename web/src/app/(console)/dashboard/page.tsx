import Link from "next/link";
import { StatusPill } from "@/components/status-pill";
import { NavIcon } from "@/components/ui/nav-icon";
import { getControlPlaneHealth, getLifecycle, getNodes } from "@/lib/control-plane";
import { runtimeLabel } from "@/lib/node-runtime";
export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  const [health, nodes] = await Promise.all([getControlPlaneHealth(), getNodes()]);
  const lifecycle = await Promise.all(nodes.map(node => getLifecycle(node.id).catch(() => null)));
  const online = lifecycle.filter(item => item?.online).length;
  const healthy = lifecycle.filter(item => item?.online && item.health_fresh && item.healthy && item.desired_generation === item.applied_generation).length;
  const unknown = lifecycle.filter(item => !item).length;
  const attention = nodes.length - healthy;
  const percentage = nodes.length ? Math.round(online / nodes.length * 100) : 0;
  return <>
    <header className="page-header">
      <div><div className="eyebrow">ВАША СЕТЬ ПОД КОНТРОЛЕМ</div><h1>Обзор инфраструктуры</h1><p>Серверы, подключения и состояние вашей VPN-сети.</p></div>
      <Link className="button primary" href="/nodes/new"><span aria-hidden="true">＋</span> Добавить сервер</Link>
    </header>
    <section className="overview-hero">
      <div className="hero-copy"><span className="hero-kicker">PAUK NETWORK</span><h2>{!nodes.length ? "Ваша сеть начинается здесь" : attention === 0 ? "Серверы на связи. Вы управляете." : "Держим вашу сеть в поле зрения"}</h2><p>{!nodes.length ? "Подключите первый сервер, создайте доступ для клиентов и управляйте сетью в одной панели." : attention === 0 ? "Все серверы передают актуальные данные. Конфигурации применены, агенты на связи." : `Требуют проверки: ${attention}. Откройте состояние системы, чтобы узнать подробности.${unknown ? ` Нет данных: ${unknown}.` : ""}`}</p>
        <Link href={nodes.length ? "/operations" : "/nodes/new"} className="hero-link">{nodes.length ? "Проверить состояние системы" : "Подключить первый сервер"} <span aria-hidden="true">↗</span></Link>
      </div>
      <div className="network-visual" aria-label={`${online} из ${nodes.length} серверов на связи`}>
        <svg viewBox="0 0 220 140" fill="none" aria-hidden="true"><path d="m20 34 78 34 62-47M98 68l92 23M98 68l-39 54M98 68l35 59" stroke="currentColor" strokeWidth="1" /><circle cx="20" cy="34" r="9" /><circle cx="160" cy="21" r="9" /><circle cx="190" cy="91" r="9" /><circle cx="59" cy="122" r="9" /><circle cx="133" cy="127" r="6" /><circle cx="98" cy="68" r="27" className="network-hub" /><path d="M88 62h20v12H88zM93 68h10" stroke="currentColor" strokeWidth="2" /></svg>
        <div><strong>{nodes.length ? `${percentage}%` : "—"}</strong><span>серверов на связи</span></div>
      </div>
    </section>
    <section className="metric-grid" aria-label="Показатели сети">
      <article className="metric-card"><div className="metric-top"><span>Всего серверов</span><NavIcon name="nodes" width={20} height={20} /></div><strong>{nodes.length}</strong><small>В вашем рабочем пространстве</small></article>
      <article className="metric-card"><div className="metric-top"><span>На связи</span><NavIcon name="activity" width={20} height={20} /></div><strong>{online}<span className="metric-unit">/ {nodes.length}</span></strong><small><i className="indicator good" />Агенты передают данные</small></article>
      <article className="metric-card"><div className="metric-top"><span>Требуют внимания</span><NavIcon name="shield" width={20} height={20} /></div><strong>{attention}</strong><small>{attention ? "Ожидание, сбой или нет данных" : "Отклонений не обнаружено"}</small></article>
      <article className="metric-card"><div className="metric-top"><span>Панель управления</span><NavIcon name="core" width={20} height={20} /></div><strong className="metric-version">{health.version}</strong><small><StatusPill value={health.status} /></small></article>
    </section>
    <div className="overview-bottom">
      <section className="panel fleet-panel"><div className="panel-header"><div><h2>Ваши серверы <span className="inline-count">{nodes.length}</span></h2><p>Текущее состояние подключений</p></div><Link className="text-link" href="/nodes">Все серверы ↗</Link></div>
        <div className="fleet-list">{nodes.slice(0, 6).map((node,index) => <Link className="fleet-row" key={node.id} href={`/nodes/${node.id}`}><span className="server-symbol"><NavIcon name="nodes" width={21} height={21} /></span><span className="fleet-name"><strong>{node.name}</strong><small>{runtimeLabel(node.runtime_core ?? "xray")} · {node.os_name ?? "Ожидает подключения"}</small></span><StatusPill value={lifecycle[index]?.state ?? "unknown"} /><span className="fleet-arrow" aria-hidden="true">↗</span></Link>)}
          {!nodes.length && <div className="empty-state"><NavIcon name="nodes" width={36} height={36} /><h3>Подключите первый сервер</h3><p>Панель выдаст команду установки и покажет результат подключения.</p><Link href="/nodes/new" className="button primary">Добавить сервер</Link></div>}
        </div>
      </section>
      <section className="panel quick-panel"><div className="panel-header"><h2>Быстрые действия</h2></div><Link className="quick-action" href="/clients"><span className="quick-symbol"><NavIcon name="clients" width={21} height={21} /></span><span><strong>Управление клиентами</strong><small>Доступы, подписки и сроки</small></span><span aria-hidden="true">↗</span></Link><Link className="quick-action" href="/access-plans"><span className="quick-symbol"><NavIcon name="shield" width={21} height={21} /></span><span><strong>Группы доступа</strong><small>Сервисы и правила подключения</small></span><span aria-hidden="true">↗</span></Link><Link className="quick-action" href="/core-updates"><span className="quick-symbol"><NavIcon name="core" width={21} height={21} /></span><span><strong>Обновления</strong><small>Версии и установка VPN-ядер</small></span><span aria-hidden="true">↗</span></Link></section>
    </div>
  </>;
}
