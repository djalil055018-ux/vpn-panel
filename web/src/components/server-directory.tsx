"use client";
import Link from "next/link";
import { useState } from "react";
import { StatusPill } from "@/components/status-pill";
import { NodeDelete } from "@/components/node-delete";
import { NodeRename } from "@/components/node-rename";
import { NodeReboot } from "@/components/node-reboot";
import { NavIcon } from "@/components/ui/nav-icon";
import { agentSupportsNodeReboot, runtimeLabel } from "@/lib/node-runtime";
import type { Lifecycle, NodeRecord } from "@/lib/control-plane";

type Server = { node: NodeRecord; lifecycle: Lifecycle | null };
function ready(item: Server) {
  const life = item.lifecycle;
  return life?.online && life.health_fresh && life.healthy && life.desired_generation === life.applied_generation;
}
export function ServerDirectory({ servers, deleted, canDelete, canRename = false, canReboot = false, totalServers = servers.length }: { servers: Server[]; deleted: boolean; canDelete: boolean; canRename?: boolean; canReboot?: boolean; totalServers?: number }) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const filters = [
    { key: "all", label: "Все серверы", count: servers.length },
    { key: "online", label: "На связи", count: servers.filter(item => item.lifecycle?.online).length },
    { key: "attention", label: "Требуют внимания", count: servers.filter(item => !ready(item)).length },
  ];
  const visible = servers.filter(item => {
    const matches = `${item.node.name} ${runtimeLabel(item.node.runtime_core ?? "xray")}`.toLocaleLowerCase("ru").includes(search.toLocaleLowerCase("ru").trim());
    return matches && (filter === "all" || (filter === "online" ? item.lifecycle?.online : !ready(item)));
  });
  return <section aria-label="Каталог серверов">
    <div className="directory-tools">
      <div className="directory-filters" aria-label="Фильтр состояния">{(deleted ? filters.slice(0,1) : filters).map(item => <button type="button" key={item.key} aria-pressed={filter === item.key} onClick={() => setFilter(item.key)}>{item.label}<span>{item.count}</span></button>)}</div>
      <label className="directory-search"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true"><circle cx="10" cy="10" r="6" /><path d="m15 15 5 5" /></svg><input type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder="Найти сервер или ядро" aria-label="Поиск серверов" /></label>
    </div>
    <div className="server-grid">{visible.map(({ node, lifecycle: life }) => {
      const synced = life && life.desired_generation === life.applied_generation;
      const fresh = life?.health_fresh;
      return <article className="server-card" key={node.id}>
        <div className="server-card-heading"><span className="server-symbol"><NavIcon name="nodes" width={23} height={23} /></span><StatusPill value={deleted ? "retired" : life?.state ?? "unknown"} /></div>
        <Link className="server-card-title" href={`/nodes/${node.id}`}><h2>{node.name}</h2><span aria-hidden="true">↗</span></Link>
        <p className="server-card-platform">{node.os_name ? `${node.os_name} ${node.os_version ?? ""}` : "Ожидает первого подключения"}<span className="runtime-chip">{runtimeLabel(node.runtime_core ?? "xray")}</span></p>
        <dl className="server-card-facts"><div><dt>VPN-ядро</dt><dd>{life?.current_core_version || "Ещё не установлено"}</dd></div><div><dt>Агент</dt><dd>{node.agent_version || "Ожидает установки"}</dd></div></dl>
        <div className="server-sync"><span className={`indicator${!deleted && fresh && synced ? " good" : ""}`} /><span>{deleted ? "Доступ сервера отозван" : !life ? "Не удалось проверить состояние" : !life.registered ? "Выполните команду подключения" : !life.online ? "Агент не выходит на связь" : life.desired_generation === 0 ? "Подключён. Настройте VPN" : !fresh ? "Ожидаем свежие данные" : synced ? "Настройки синхронизированы" : "Применяются новые настройки"}</span></div>
        <div className="server-card-footer"><Link href={`/nodes/${node.id}`} className="button">{!deleted && life?.registered && life.desired_generation === 0 ? "Настроить сервер" : "Открыть сервер"}<span aria-hidden="true">↗</span></Link>{!deleted && canRename && <NodeRename id={node.id} name={node.name} />}{!deleted && canReboot && <NodeReboot id={node.id} name={node.name} disabled={!agentSupportsNodeReboot(life?.agent_version ?? node.agent_version) || !ready({ node, lifecycle: life })} disabledReason={!agentSupportsNodeReboot(life?.agent_version ?? node.agent_version) ? "Установите агент с поддержкой перезагрузки" : undefined} />}{!deleted && canDelete && <NodeDelete id={node.id} name={node.name} online={!!life?.online} decommissioning={life?.state === "decommissioning"} desiredGeneration={life?.desired_generation ?? 0} appliedGeneration={life?.applied_generation ?? 0} />}</div>
      </article>;
    })}</div>
    {visible.length === 0 && <div className="panel empty-state"><NavIcon name="nodes" width={36} height={36} /><h2>{servers.length ? "Серверы не найдены" : totalServers ? "В этой категории пока нет серверов" : deleted ? "Удалённых серверов пока нет" : "Добавьте ваш первый сервер"}</h2><p>{servers.length ? "Попробуйте другое имя или измените фильтр." : totalServers ? "Выберите другую категорию или настройте подходящий VPN-сервис." : "Подключение займёт три шага. Мы подскажем, что выполнить на сервере."}</p>{servers.length ? <button className="button" type="button" onClick={() => { setSearch(""); setFilter("all"); }}>Сбросить фильтры</button> : !deleted && !totalServers && <Link href="/nodes/new" className="button primary">Добавить сервер</Link>}</div>}
    <p className="directory-count" role="status">Показано {visible.length} из {servers.length}</p>
  </section>;
}
