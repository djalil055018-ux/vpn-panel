"use client";
import {useEffect,useState,useTransition} from "react";
import type {NodeSecurityStatus,NodeReadiness,NodeSecurityPolicy} from "@/lib/node-security";
import {nodeSecurityReportFreshAt} from "@/lib/node-security";
import {reloadNodeSecurityAction,saveNodeSecurityAction} from "@/app/node-security-actions";
const certLabels:Record<string,string>={not_applicable:"Не требуется для этого транспорта",missing:"Не назначен",unavailable:"Недоступен",unknown:"Нет подтверждения срока",expired:"Вне срока действия",expiring:"Истекает в течение 14 дней",valid:"Действует"};
const diagnosticLabels:Record<string,string>={agent_registration:"Регистрация агента",heartbeat:"Связь с агентом",health:"Состояние VPN-процесса",generation:"Применение конфигурации",core:"Версия VPN-ядра",rollback:"Резерв для отката",latest_deployment:"Последнее применение"};
function yes(v:boolean|null|undefined,good:string,bad:string){return v===true?good:v===false?bad:"Нет измерения";}
export function NodeSecurityManager({initial,initialReadiness}:{initial:NodeSecurityStatus;initialReadiness:NodeReadiness|null}){
 const[data,setData]=useState(initial),[readiness,setReadiness]=useState(initialReadiness),[message,setMessage]=useState(""),[pending,start]=useTransition();
 const[now,setNow]=useState<number|null>(null);
 useEffect(()=>{const tick=()=>setNow(Date.now());const first=setTimeout(tick,0),timer=setInterval(tick,5000);return()=>{clearTimeout(first);clearInterval(timer);};},[]);
 function refresh(){start(async()=>{const r=await reloadNodeSecurityAction(data.node_id);if(r.ok){setNow(Date.now());setData(r.security);setReadiness(r.readiness);}setMessage(r.message);});}
 function save(p:NodeSecurityPolicy){start(async()=>{const r=await saveNodeSecurityAction(data.node_id,p);if(r.ok)setData(r.security);setMessage(r.message);});}
 useEffect(()=>{let active=true;const timer=setInterval(()=>{void reloadNodeSecurityAction(initial.node_id).then(r=>{if(active&&r.ok){setNow(Date.now());setData(r.security);setReadiness(r.readiness);}}).catch(()=>{});},60000);return()=>{active=false;clearInterval(timer);};},[initial.node_id]);
 const report=data.report,reportFresh=now===null?data.fresh&&!!data.received_at:nodeSecurityReportFreshAt(data,now),fresh=reportFresh&&report?.policy_revision===data.policy.revision;
 const state=!report?"Ожидаем агент 0.2.50 или новее":!reportFresh?"Отчёт устарел":!fresh?"Ожидаем применения настройки":data.mitigation_ready?"Меры снижения риска TCP подтверждены":"Требуется внимание";
 return <section className="panel node-security" aria-label="Безопасность и готовность ноды">
 <div className="panel-header"><div><h2>Безопасность и готовность</h2><p role="status">{state}</p></div><button className="button" disabled={pending} onClick={refresh}>Обновить проверку</button></div>
 <div className="protocol-form-grid"><label><span>Защита TCP на ноде</span><select aria-label="Защита TCP на ноде" value={data.policy.mode} disabled={pending} onChange={e=>save({...data.policy,mode:e.target.value as "audit"|"protect"})}><option value="audit">Проверять состояние</option><option value="protect">Поддерживать защиту включённой</option></select></label><label><span>Массовое обновление агента</span><select aria-label="Массовое обновление агента" value={String(data.policy.update_hold)} disabled={pending} onChange={e=>save({...data.policy,update_hold:e.target.value==="true"})}><option value="false">Разрешено по общей политике</option><option value="true">Исключить эту ноду</option></select></label></div>
 <p>Защита отключает MPTCP и миграцию TCP-запросов, фильтрует TCP с IPv4 options и сохраняется после перезагрузки. Режим проверки сохраняет уже установленную защиту. Исключение из массового обновления относится к агенту этой ноды.</p>
 <div className="node-security-facts" aria-label="Результаты проверки защиты">
 <div><span>Ядро Linux</span><strong>{report?.kernel||"Нет измерения"}</strong></div>
 <div><span>MPTCP</span><strong>{yes(report?.mptcp_disabled,"Отключён","Включён")}</strong></div>
 <div><span>Миграция TCP-запросов</span><strong>{yes(report?.tcp_migrate_disabled,"Отключена","Включена")}</strong></div>
 <div><span>Фильтр IPv4 options</span><strong>{yes(report?.ipv4_options_filter,"Подтверждён","Не подтверждён")}</strong></div>
 <div><span>Слушающие сокеты MPTCP</span><strong>{report?.mptcp_listeners??"Нет измерения"}</strong></div>
 <div><span>Inode занято</span><strong>{report?.inodes_used_percent==null?"Нет измерения":`${report.inodes_used_percent.toFixed(1)}%`}</strong></div>
 <div><span>Лимит файлов агента</span><strong>{report?.nofile_soft??"Нет измерения"}</strong></div>
 <div><span>Публичные порты управления¹</span><strong>{report?.public_management_listeners??"Нет измерения"}</strong></div>
 </div>
 {report&&<p>{data.received_at?`Отчёт получен: ${new Date(data.received_at).toLocaleString("ru-RU")}. `:""}{!fresh&&"Последние измерения пока не подтверждают текущее состояние. "}{report.apply_result==="conflict"?"Обнаружены изменённые владельцем файлы или правила: агент сохранил их. ":report.apply_result==="unavailable"?"Средства проверки или применения недоступны. ":report.apply_result==="apply_failed"?"Не все меры удалось применить. ":""}{(report.mptcp_listeners??0)>0&&"Старый MPTCP-сокет требует контролируемого перезапуска владеющего им сервиса. "}{(report.public_management_listeners??0)>0&&"Проверьте привязку портов управления и правила доступа. "}{(report.inodes_used_percent??0)>90&&"Мало свободных inode: проверьте накопление журналов и мелких файлов."}</p>}
 <p className="protocol-edit-note">Эти меры уменьшают риск CVE-2026-98432 и не заменяют исправленное ядро. На 9 ноября 2026 исправление Ubuntu 24.04 ещё готовится. <a href="https://ubuntu.com/security/CVE-2026-98432" target="_blank" rel="noopener noreferrer">Статус Ubuntu</a>. ¹ Проверяется привязка 8080, 10085 и 10086 к нелокальным адресам; это не внешний сетевой скан.</p>
 <details><summary>Готовность подключений</summary><p>Проверка объясняет состояние на сервере. Доступность из мобильной сети и передачу данных следует проверять отдельно в приложении.</p>
 {readiness?<><ul>{readiness.diagnostics.checks.map(c=><li key={c.code}>{diagnosticLabels[c.code]??c.code}: {c.status==="ok"?"подтверждено":c.status==="error"?"ошибка":"проверьте состояние"}</li>)}</ul><div className="table-wrap"><table><thead><tr><th>Подключение</th><th>Активных назначений</th><th>Сертификат TLS</th><th>Резервные входы</th></tr></thead><tbody>{readiness.services.map(s=><tr key={s.id}><td><strong>{s.name}</strong><small style={{display:"block"}}>{s.protocol.toUpperCase()} · {s.enabled?"включено":"выключено"}</small></td><td>{s.active_assignments}{s.active_assignments===0&&<small style={{display:"block"}}>Проверьте группу доступа, если профиль должен выдаваться</small>}</td><td>{certLabels[s.certificate]??"Нет подтверждения"}</td><td>{s.ingress_mode==="enabled"?(s.ingress_ready?"Оба входа готовы":"Ожидаем подтверждения входов"):s.ingress_mode==="direct"?"Прямое подключение":s.ingress_mode==="legacy"?"Текущий маршрут":"Нет данных о входах"}</td></tr>)}</tbody></table></div>{!readiness.services.length&&<p>На ноде нет протоколов.</p>}<p className="protocol-edit-note">Назначения учитывают активных клиентов, срок доступа и включённые группы. Проверка не меняет права клиентов и не отменяет тарифные условия.</p></>:<p>Не удалось получить готовность подключений.</p>}
 </details>{message&&<p role="status">{message}</p>}
 </section>;
}
