"use client";
import {useState,useTransition} from "react";
import {saveIngressAction,checkIngressEntryAction,checkIngressDNSAction,deleteIngressEntryAction} from "@/app/ingress-actions";
import type {IngressConfig,IngressDNS} from "@/lib/ingress-types";
import "@/app/ingress.css";
import {IngressProvisioner} from "@/components/ingress-provisioner";
import type {IngressProvisionOverview} from "@/lib/ingress-types";

export function IngressManager({initial,provision,origin}:{origin:string|null;initial:IngressConfig;provision:IngressProvisionOverview|null}){
 const [config,setConfig]=useState(initial),[primary,setPrimary]=useState(initial.primary_id),[secondary,setSecondary]=useState(initial.secondary_id),[vpn,setVPN]=useState(initial.vpn_enabled),[web,setWeb]=useState(initial.web_enabled),[interval,setInterval]=useState(initial.probe_interval_seconds),[pending,start]=useTransition(),[message,setMessage]=useState(""),[error,setError]=useState(false),[dns,setDNS]=useState<IngressDNS|null>(null);
 const preparing=Boolean(provision?.runs.some(r=>r.status==="running"));const busy=pending||preparing;
 const preparedEntries=config.entries.filter(e=>e.id!=="pauk-direct-publication");
 const readyEntries=preparedEntries.filter(e=>e.ready);
 const first=preparedEntries.find(e=>e.id===primary),second=preparedEntries.find(e=>e.id===secondary);
 const hosts=[config.panel_host,config.subscription_host,...config.legacy_hosts];
 const addresses=[first?.address,...(web?[second?.address]:[])].filter((a):a is string=>Boolean(a));
 const dirty=primary!==config.primary_id||secondary!==config.secondary_id||vpn!==config.vpn_enabled||web!==config.web_enabled||interval!==config.probe_interval_seconds;
 const hasPair=readyEntries.length>=2;
 const reserveActive=config.vpn_enabled||config.web_enabled;
 const mayRemove=!reserveActive&&!dirty;
 function feedback(text:string,failed=false){setMessage(text);setError(failed);}
 function save(){start(async()=>{const result=await saveIngressAction({revision:config.revision,primary_id:primary,secondary_id:secondary,vpn_enabled:vpn,web_enabled:web,probe_interval_seconds:interval});feedback(result.message,!result.ok);if(result.ok){setConfig(result.data);setDNS(null);}});}
 function check(id:string){start(async()=>{const result=await checkIngressEntryAction(id);feedback(result.message,!result.ok);if(result.ok)setConfig(result.data);});}

 function remove(id:string,name:string){
  if(!window.confirm(`Удалить вход «${name}» из панели?`))return;
  start(async()=>{
   const result=await deleteIngressEntryAction(id,config.revision);
   feedback(result.message,!result.ok);
   if(result.ok){
    const updated=result.data;
    setConfig(updated);setPrimary(updated.primary_id);setSecondary(updated.secondary_id);
    setVPN(updated.vpn_enabled);setWeb(updated.web_enabled);
    setInterval(updated.probe_interval_seconds);setDNS(null);
   }
  });
 }
 function checkDNS(){start(async()=>{const result=await checkIngressDNSAction();feedback(result.message,!result.ok);if(result.ok)setDNS(result.data);});}
 async function copyDNS(){try{await navigator.clipboard.writeText(hosts.flatMap(host=>addresses.map(ip=>`${host}. 300 IN A ${ip}`)).join("\n"));feedback("DNS-записи скопированы.");}catch{feedback("Не удалось скопировать. Используйте таблицу ниже.",true);}}
 return <div className="ingress-workspace" aria-busy={pending}>
  {message&&<p role="status" className={error?"ingress-feedback error":"ingress-feedback"}>{message}</p>}
  <section className="panel ingress-settings"><div className="ingress-section-title"><div><p className="eyebrow">СХЕМА ПОДКЛЮЧЕНИЯ</p><h2>Основной и резервный вход</h2></div><span className="ingress-badge">{readyEntries.length} подготовлено</span></div>
   <div className="ingress-selection"><label>Основной вход<select aria-label="Основной вход" value={first?.id??""} disabled={busy||!hasPair} onChange={e=>{const id=e.target.value;setPrimary(id);if(id===secondary)setSecondary(first?.id??"");}}>{!first&&<option value="">Не выбран</option>}{readyEntries.map(e=><option key={e.id} value={e.id}>{e.name} · {e.address}</option>)}</select></label><span className="ingress-swap"><button className="button ghost" type="button" disabled={busy||!first||!second} onClick={()=>{setPrimary(secondary);setSecondary(primary);}} aria-label="Поменять основной и резервный входы местами">⇄</button></span><label>Резервный вход<select aria-label="Резервный вход" value={second?.id??""} disabled={busy||!hasPair} onChange={e=>setSecondary(e.target.value)}>{!second&&<option value="">Не выбран</option>}{readyEntries.map(e=><option key={e.id} value={e.id} disabled={e.id===primary}>{e.name} · {e.address}</option>)}</select></label></div>
   <label className="ingress-toggle"><span><strong>Автоматический резерв в VPN</strong><small>В поддерживаемых полных конфигурациях приложение проверяет оба входа. Обычные VLESS-ссылки получают отдельный вариант «второй вход».</small></span><input type="checkbox" checked={vpn} disabled={busy||(!hasPair&&!vpn)} onChange={e=>setVPN(e.target.checked)}/></label>
   <label className="ingress-toggle"><span><strong>Резерв для панели и подписок</strong><small>Оба адреса публикуются в DNS. После отказа одного адреса браузер или приложение должно попробовать другой. Изменения DNS выполняются у провайдера.</small></span><input type="checkbox" checked={web} disabled={busy||(!hasPair&&!web)} onChange={e=>setWeb(e.target.checked)}/></label>
   <label className="ingress-interval">Интервал проверки входов в Xray, секунд<input type="number" min={10} max={300} step={1} value={interval} disabled={busy} onChange={e=>setInterval(Number(e.target.value))}/></label>
   <div className="ingress-actions"><button type="button" className="button primary" disabled={busy||!first||!second||primary===secondary||!Number.isInteger(interval)||interval<10||interval>300} onClick={save}>{pending?"Выполняется…":"Сохранить настройки"}</button><span>{dirty?"Есть несохранённые изменения":"Настройки сохранены"}</span></div>
   <p className="ingress-note">Новые настройки VPN появятся после обновления подписки в приложении. Действующие подключения сохраняют ранее полученную конфигурацию.</p>
  </section>
  <IngressProvisioner initial={provision} config={config} settingsDirty={dirty} origin={origin}/>
  <section className="ingress-entry-grid" aria-label="Подготовленные входы">{preparedEntries.length===0&&<p className="ingress-note">Подготовленных входов пока нет.</p>}{preparedEntries.map(entry=><article className="panel ingress-entry" key={entry.id}><div className="ingress-entry-heading"><h2>{entry.name}</h2><span className="ingress-badge">{entry.id===config.primary_id?"Основной":entry.id===config.secondary_id?"Резервный":"Доступен"}</span></div><p className="ingress-address">{entry.address}</p><dl><div><dt>Подписки</dt><dd>HTTPS · {entry.https_port}</dd></div><div><dt>Панель</dt><dd>HTTPS · {entry.panel_port}</dd></div><div><dt>Подготовка</dt><dd>{entry.ready?"Завершена":"Не завершена"}</dd></div></dl><p className={entry.check_status==="ok"?"ingress-check good":"ingress-check"}>{entry.check_status==="ok"?"Проверка с сервера пройдена":entry.check_status==="unreachable_from_panel"?"Доступ с сервера панели не подтверждён":"Вход подготовлен и проверен при установке"}</p>{entry.checked_at&&<p className="ingress-note">Последняя проверка: {new Date(entry.checked_at).toLocaleString("ru-RU",{timeZone:"Europe/Moscow"})} МСК</p>}<div className="ingress-actions"><button type="button" className="button ghost" disabled={busy} onClick={()=>check(entry.id)}>Проверить с сервера</button><button type="button" className="button ghost" disabled={busy||!mayRemove} onClick={()=>remove(entry.id,entry.name)}>Удалить вход</button></div>{reserveActive&&<p className="ingress-note">Перед удалением отключите оба вида резерва и сохраните настройки.</p>}<p className="ingress-note">Проверка из дата-центра не определяет блокировку у мобильного оператора.</p></article>)}</section>
  {first&&second&&<section className="panel ingress-dns"><div className="ingress-section-title"><div><p className="eyebrow">ПАНЕЛЬ И ОБНОВЛЕНИЕ ПОДПИСОК</p><h2>DNS для выбранной схемы</h2></div><div className="ingress-actions"><button type="button" className="button ghost" onClick={copyDNS} disabled={busy||dirty}>Скопировать записи</button><button type="button" className="button" onClick={checkDNS} disabled={busy||dirty}>Проверить DNS</button></div></div>
   <p>{web?"У каждого имени должны быть оба IP. Существующую A-запись сохраняйте и добавляйте вторую.":"Для выбранной схемы у каждого имени требуется IP основного входа."} Рекомендуемый TTL — 300 секунд, если он поддерживается провайдером.</p>
   {dirty&&<p className="ingress-note">Сначала сохраните выбранную схему.</p>}
   {dns&&<p role="status" className={dns.all_match?"ingress-feedback":"ingress-feedback error"}>{dns.all_match?"DNS соответствует сохранённой схеме.":"DNS пока не соответствует схеме. Проверьте записи у провайдера и дождитесь обновления кеша."}</p>}
   <div className="ingress-table-wrap"><table><thead><tr><th>Имя</th><th>Тип</th><th>Требуемые значения</th>{dns&&<th>Получено при проверке</th>}</tr></thead><tbody>{hosts.map(host=><tr key={host}><td>{host}</td><td>A</td><td>{addresses.map(ip=><code key={ip}>{ip}</code>)}</td>{dns&&<td>{dns.records.find(r=>r.host===host)?.observed.join(", ")||"Нет A-записей"}</td>}</tr>)}</tbody></table></div>
   <p className="ingress-note">Кнопка проверки не изменяет DNS. Ссылки подписок и домены сохраняются.</p>
  </section>}
 </div>;
}

