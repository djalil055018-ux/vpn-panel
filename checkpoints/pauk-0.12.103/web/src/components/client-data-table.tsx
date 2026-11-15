"use client";

import { useRef, useState, useTransition, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { NavIcon } from "@/components/ui/nav-icon";
import type { VPNClientRecord, VPNClientUsage } from "@/lib/control-plane";
import type { DeviceCategory } from "@/lib/device-categories";

type Props = {
  clients: VPNClientRecord[];
  usages: (VPNClientUsage | null)[];
  clientCategories: Record<string, DeviceCategory[]>;
  onCreate: () => void;
  details: (client: VPNClientRecord, index: number) => ReactNode;
};
type Column = "name" | "id" | "status" | "node" | "expires" | "traffic" | "telegram" | "tag" | "groups" | "first" | "reset" | "online" | "lifetime";
const columns: { key: Column; label: string }[] = [
  {key:"name",label:"Пользователь"},{key:"id",label:"ID"},{key:"status",label:"Статус"},
  {key:"node",label:"Последняя нода"},{key:"expires",label:"Истекает"},{key:"traffic",label:"Израсходовано"},
  {key:"telegram",label:"Telegram ID"},{key:"tag",label:"Тег"},{key:"groups",label:"Группы доступа"},
  {key:"first",label:"Первое подключение"},{key:"reset",label:"Сброс трафика"},{key:"online",label:"Был онлайн"},
  {key:"lifetime",label:"Трафик за всё время"},
];
const statuses = [
  {key:"all",label:"Всего",icon:"clients" as const},
  {key:"active",label:"Активны",icon:"activity" as const},
  {key:"expired",label:"Истекли",icon:"recovery" as const},
  {key:"quota_exceeded",label:"Лимит исчерпан",icon:"billing" as const},
  {key:"disabled",label:"Отключены",icon:"shield" as const},
];
function statusOf(client: VPNClientRecord) {
  if(client.remnawave_hold) return client.directory?.source_status?.toLowerCase().replace("limited","quota_exceeded") ?? "held";
  return client.effective_status || client.status;
}
function statusLabel(status: string) { return ({active:"Активен",expired:"Истёк",quota_exceeded:"Лимит исчерпан",disabled:"Отключён",held:"Ожидает переноса"} as Record<string,string>)[status] ?? "Неизвестно"; }
function bytes(value: number | null | undefined) {
  if(value==null || !Number.isFinite(value)) return "Нет данных";
  if(value===0)return "0 B";
  const unit=Math.max(0,Math.min(4,Math.floor(Math.log(Math.max(1,value))/Math.log(1024))));
  return `${(value/1024**unit).toLocaleString("ru-RU",{maximumFractionDigits:unit?2:0})} ${["B","KiB","MiB","GiB","TiB"][unit]}`;
}
function date(value: string | null | undefined, never="Никогда") {
  if(value===null)return never;
  if(!value || !Number.isFinite(Date.parse(value)))return "Нет данных";
  return new Date(value).toLocaleString("ru-RU",{day:"2-digit",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit",timeZone:"Europe/Moscow"});
}
function UsageBar({usage}:{usage:VPNClientUsage|null|undefined}) {
  if(!usage)return <span className="client-cell-muted">Нет данных</span>;
  const limit=usage.traffic_limit_bytes??usage.monthly_limit_bytes;
  const percentage=limit>0?Math.min(100,Math.max(0,usage.used_bytes/limit*100)):0;
  return <div className={`client-traffic ${usage.quota_exceeded?"is-limited":""}`}>
    <div><strong>{bytes(usage.used_bytes)}</strong><span>{limit>0?`${percentage.toLocaleString("ru-RU",{maximumFractionDigits:1})}%`:"Без лимита"}</span></div>
    <div className="client-traffic-track" role={limit>0?"progressbar":undefined} aria-label="Использованный трафик" aria-valuemin={limit>0?0:undefined} aria-valuemax={limit>0?100:undefined} aria-valuenow={limit>0?Math.round(percentage):undefined}><i style={{width:limit>0?`${percentage}%`:"100%"}}/></div>
    <div><span>{usage.reset_policy==="NO_RESET"?"Без сброса":"За месяц"}</span><span>{limit>0?`из ${bytes(limit)}`:"∞"}</span></div>
  </div>;
}

export function ClientDataTable({clients,usages,clientCategories,onCreate,details}:Props) {
  const router=useRouter();const [refreshing,startRefresh]=useTransition();
  const [deviceFilter,setDeviceFilter]=useState<DeviceCategory|"all">("smartphone");
  const [filter,setFilter]=useState("all");const [query,setQuery]=useState("");
  const [filters,setFilters]=useState<Partial<Record<Column,string>>>({});
  const [sort,setSort]=useState<{column:Column;descending:boolean}>({column:"id",descending:true});
  const [hidden,setHidden]=useState<Column[]>([]);const [page,setPage]=useState(0);const [size,setSize]=useState(25);
  const [selected,setSelected]=useState<string|null>(null);const dialog=useRef<HTMLDialogElement>(null);
  const activeColumns=columns.filter(column=>!hidden.includes(column.key));
  const allRows=clients.map((client,index)=>({client,index,usage:usages[index]}));
  const categoryRows=deviceFilter==="all"?allRows:allRows.filter(row=>clientCategories[row.client.id]?.includes(deviceFilter));
  const held=categoryRows.filter(row=>row.client.remnawave_hold).length;
  const deviceCounts={smartphone:allRows.filter(row=>clientCategories[row.client.id]?.includes("smartphone")).length,router:allRows.filter(row=>clientCategories[row.client.id]?.includes("router")).length};
  function value(row:typeof allRows[number],column:Column):string|number {
    const c=row.client,m=c.directory;
    switch(column){
      case "name":return c.name;
      case "id":return m?.numeric_id??"";
      case "status":return statusOf(c);
      case "node":return m?.last_node_name??"";
      case "expires":return c.expires_at?Date.parse(c.expires_at):Number.MAX_SAFE_INTEGER;
      case "traffic":return row.usage?.used_bytes??-1;
      case "telegram":return m?.telegram_id??"";
      case "tag":return m?.tag??"";
      case "groups":return m?.groups?.join(" ")??"";
      case "first":return m?.first_connected_at?Date.parse(m.first_connected_at):-1;
      case "reset":return m?.last_traffic_reset_at?Date.parse(m.last_traffic_reset_at):-1;
      case "online":return m?.last_online_at?Date.parse(m.last_online_at):-1;
      case "lifetime":return m?.lifetime_used_bytes??-1;
    }
  }
  const matching=categoryRows.filter(row=>{
    if(filter!=="all"&&(filter==="held"?!row.client.remnawave_hold:statusOf(row.client)!==filter))return false;
    const text=[row.client.name,row.client.directory?.numeric_id,row.client.directory?.telegram_id,row.client.directory?.tag,row.client.directory?.last_node_name,...row.client.directory?.groups??[]].join(" ").toLocaleLowerCase("ru");
    if(!text.includes(query.trim().toLocaleLowerCase("ru")))return false;
    return Object.entries(filters).every(([key,term])=>!term||String(value(row,key as Column)).toLocaleLowerCase("ru").includes(term.toLocaleLowerCase("ru")));
  }).sort((a,b)=>{
    const x=value(a,sort.column),y=value(b,sort.column);
    const comparison=typeof x==="number"&&typeof y==="number"?x-y:String(x).localeCompare(String(y),"ru",{numeric:true});
    return (sort.descending?-comparison:comparison)||a.client.name.localeCompare(b.client.name,"ru");
  });
  const totalPages=Math.max(1,Math.ceil(matching.length/size)),currentPage=Math.min(page,totalPages-1);
  const visible=matching.slice(currentPage*size,(currentPage+1)*size);
  const selectedRow=allRows.find(row=>row.client.id===selected);
  function reset(){setQuery("");setFilters({});setFilter("all");setDeviceFilter("all");setPage(0);}
  function cell(row:typeof allRows[number],key:Column):ReactNode {
    const c=row.client,m=c.directory,status=statusOf(c);
    switch(key){
      case "name":return <button type="button" className="client-name-button" aria-label={`Управление: ${c.name}`} onClick={()=>{setSelected(c.id);dialog.current?.showModal();}}><i className={`client-presence ${m?.connection_state??"unknown"}`} title={m?.connection_state==="online"?"Онлайн по последнему наблюдению":m?.connection_state==="never"?"Ещё не подключался":"Текущий онлайн не подтверждён"}/><span><strong>{c.name}</strong><small>{c.remnawave_hold?"Данные исходной панели":m?.connection_state==="never"?"Ещё не подключался":m?.last_online_at?`Был онлайн ${date(m.last_online_at)}`:"Наблюдений о подключении нет"}</small></span></button>;
      case "id":return <span className="client-tabular">{m?.numeric_id??"—"}</span>;
      case "status":return <span className={`client-status-pill ${status}`}><NavIcon name={status==="active"?"activity":status==="disabled"?"shield":"recovery"} width={14} height={14}/>{statusLabel(status)}</span>;
      case "node":return <span className="client-node-name">{m?.last_node_name?<><NavIcon name="nodes" width={15} height={15}/>{m.last_node_name}</>:<span className="client-cell-muted">—</span>}</span>;
      case "expires":return <span className="client-date">{date(c.expires_at??null,"Бессрочно")}</span>;
      case "traffic":return <UsageBar usage={row.usage}/>;
      case "telegram":return <span className="client-tabular">{m?.telegram_id??"—"}</span>;
      case "tag":return m?.tag?<span className="client-tag">{m.tag}</span>:<span className="client-cell-muted">—</span>;
      case "groups":return <span className="client-groups">{m?.groups?.length?m.groups.map(group=><span key={group}>{group}</span>):<span className="client-cell-muted">—</span>}</span>;
      case "first":return <span className="client-date">{date(m?.first_connected_at,"Ещё не подключался")}</span>;
      case "reset":return <span className="client-date">{date(m?.last_traffic_reset_at)}</span>;
      case "online":return <span className="client-date">{date(m?.last_online_at)}</span>;
      case "lifetime":return <span className="client-tabular">{bytes(m?.lifetime_used_bytes)}</span>;
    }
  }
  return <>
    <div className="client-metrics" aria-label="Статистика клиентов">{statuses.map(item=>{const count=item.key==="all"?categoryRows.length:categoryRows.filter(row=>statusOf(row.client)===item.key).length;return <button key={item.key} type="button" className={`client-metric ${item.key}`} aria-pressed={filter===item.key} onClick={()=>{setFilter(item.key);setPage(0);}}><span className="client-metric-icon"><NavIcon name={item.icon}/></span><span><small>{item.label}</small><strong>{count}</strong></span></button>;})}</div>
    <section className="panel clients-data-panel" aria-label="Список клиентов">
      <div className="clients-data-heading"><div className="clients-data-title"><span className="client-metric-icon"><NavIcon name="clients"/></span><div><h2>Клиенты</h2><p>Подписки, подключения и трафик</p></div></div><div className="client-device-tabs" role="group" aria-label="Фильтр по типу устройства"><button type="button" aria-pressed={deviceFilter==="smartphone"} onClick={()=>{setDeviceFilter("smartphone");setPage(0);}}>Смартфоны <span>{deviceCounts.smartphone}</span></button><button type="button" aria-pressed={deviceFilter==="router"} onClick={()=>{setDeviceFilter("router");setPage(0);}}>Роутеры <span>{deviceCounts.router}</span></button><button type="button" aria-pressed={deviceFilter==="all"} onClick={()=>{setDeviceFilter("all");setPage(0);}}>Все <span>{clients.length}</span></button></div><div className="clients-data-actions"><button type="button" className="button ghost client-icon-button" aria-label="Обновить клиентов" disabled={refreshing} onClick={()=>startRefresh(()=>router.refresh())}><span className={refreshing?"is-spinning":""}>↻</span></button><button type="button" className="button primary" onClick={onCreate}><span aria-hidden="true">＋</span> Добавить клиента</button></div></div>
      <div className="clients-data-tools"><label className="directory-search"><NavIcon name="search" width={17} height={17}/><input type="search" aria-label="Поиск клиентов" placeholder="Имя, Telegram ID или тег" value={query} onChange={e=>{setQuery(e.target.value);setPage(0);}}/></label><div className="clients-table-options">{held>0&&<button className="client-held-filter" type="button" aria-pressed={filter==="held"} onClick={()=>{setFilter(filter==="held"?"all":"held");setPage(0);}}>Ожидают переноса <span>{held}</span></button>}<button type="button" className="button ghost" onClick={reset}>Сбросить фильтры</button><details className="client-columns"><summary>Колонки <span aria-hidden="true">⌄</span></summary><div>{columns.filter(c=>c.key!=="name").map(c=><label key={c.key}><input type="checkbox" checked={!hidden.includes(c.key)} onChange={e=>setHidden(e.target.checked?hidden.filter(key=>key!==c.key):[...hidden,c.key])}/>{c.label}</label>)}</div></details></div></div>
      {held>0&&<p className="client-snapshot-note"><span aria-hidden="true">ⓘ</span> Клиенты на переносе показаны по сохранённому снимку. Их подключение через PAUK ещё не включено.</p>}
      <div className="clients-table-scroll" tabIndex={0} role="region" aria-label="Таблица клиентов; дополнительные колонки доступны при прокрутке вправо"><table className="clients-data-table"><thead><tr>{activeColumns.map(c=><th key={c.key} scope="col" className={`column-${c.key}`} aria-sort={sort.column===c.key?(sort.descending?"descending":"ascending"):"none"}><button type="button" onClick={()=>{setSort({column:c.key,descending:sort.column===c.key?!sort.descending:false});setPage(0);}}>{c.label}<span aria-hidden="true">{sort.column===c.key?(sort.descending?"↓":"↑"):"↕"}</span></button></th>)}</tr><tr className="client-column-filters">{activeColumns.map(c=><th key={c.key} className={`column-${c.key}`}>{["name","id","node","telegram","tag","groups"].includes(c.key)?<input aria-label={`Фильтр: ${c.label}`} value={filters[c.key]??""} placeholder="Фильтр…" onChange={e=>{setFilters({...filters,[c.key]:e.target.value});setPage(0);}}/>:c.key==="status"?<select aria-label="Фильтр: Статус" value={filters.status??""} onChange={e=>{setFilters({...filters,status:e.target.value});setPage(0);}}><option value="">Любой</option>{statuses.filter(s=>s.key!=="all").map(s=><option key={s.key} value={s.key}>{s.label}</option>)}<option value="held">Ожидает переноса</option></select>:<span/>}</th>)}</tr></thead><tbody>{visible.map(row=><tr key={row.client.id} className={row.client.remnawave_hold?"is-held":""}>{activeColumns.map(c=><td key={c.key} className={`column-${c.key}`}>{cell(row,c.key)}</td>)}</tr>)}</tbody></table></div>
      {!visible.length&&<div className="empty-state"><NavIcon name="clients" width={32} height={32}/><h2>{categoryRows.length?"Клиенты не найдены":clients.length?"В этом разделе пока нет клиентов":"Ваш первый клиент"}</h2><p>{categoryRows.length?"Измените запрос или сбросьте фильтры.":clients.length?"Выберите другой тип устройства или откройте всех клиентов.":"Создайте клиента и назначьте ему группу доступа."}</p><button type="button" className="button" onClick={categoryRows.length?reset:clients.length?()=>{setDeviceFilter("all");setFilter("all");setPage(0);}:onCreate}>{categoryRows.length?"Сбросить фильтры":clients.length?"Показать всех клиентов":"Добавить клиента"}</button></div>}
      <div className="clients-table-footer"><span aria-live="polite">{matching.length?`${currentPage*size+1}–${Math.min((currentPage+1)*size,matching.length)}`:"0"} из {matching.length}{matching.length!==categoryRows.length?` · в разделе ${categoryRows.length}`:""}{categoryRows.length!==clients.length?` · всего ${clients.length}`:""}</span><div><label>На странице <select aria-label="Клиентов на странице" value={size} onChange={e=>{setSize(Number(e.target.value));setPage(0);}}>{[25,50,100].map(n=><option key={n}>{n}</option>)}</select></label><button type="button" className="button ghost" aria-label="Предыдущая страница" disabled={currentPage===0} onClick={()=>setPage(currentPage-1)}>‹</button><span>{currentPage+1} / {totalPages}</span><button type="button" className="button ghost" aria-label="Следующая страница" disabled={currentPage>=totalPages-1} onClick={()=>setPage(currentPage+1)}>›</button></div></div>
    </section>
    <dialog ref={dialog} className="client-profile-dialog" onClose={()=>setSelected(null)}><div className="client-dialog-heading"><div><span className="eyebrow">КАРТОЧКА КЛИЕНТА</span><h2>{selectedRow?.client.name??"Клиент"}</h2></div><button type="button" className="button ghost" aria-label="Закрыть карточку клиента" onClick={()=>dialog.current?.close()}>✕</button></div>{selectedRow&&<>{selectedRow.client.directory?.source_observed_at&&<p className="client-snapshot-note">Снимок исходной панели: {date(selectedRow.client.directory.source_observed_at)}</p>}{details(selectedRow.client,selectedRow.index)}</>}</dialog>
  </>;
}
