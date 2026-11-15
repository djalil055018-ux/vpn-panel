"use client";
import {useEffect,useState,useTransition} from "react";
import Link from "next/link";
import {ingressCompanionInstallCommand} from "@/lib/ingress-installer";
import {reloadNodeIngressAction,saveNodeIngressAction} from "@/app/protocol-ingress-actions";
import type {IngressPolicy,NodeProtocolIngress} from "@/lib/protocol-ingress";

function PolicySelect({policy,node,disabled,save}:{policy:IngressPolicy;node?:boolean;disabled:boolean;save:(value:string)=>void}){
 return <select aria-label={node?"Резервный вход по умолчанию":"Резервный вход протокола"} value={policy.mode} disabled={disabled} onChange={e=>save(e.target.value)}>
  <option value={node?"legacy":"inherit"}>{node?"Текущие маршруты":"Как на ноде"}</option>
  <option value="enabled">Основной и резервный входы</option><option value="direct">Прямое подключение</option>
 </select>;
}
export function NodeProtocolIngressManager({initial}:{initial:NodeProtocolIngress}){
 const [data,setData]=useState(initial),[message,setMessage]=useState(""),[pending,start]=useTransition();
 async function copyInstall(){try{await navigator.clipboard.writeText(ingressCompanionInstallCommand());setMessage("Команда скопирована. Выполните её один раз в root-консоли этой ноды, затем обновите состояние.");}catch{setMessage("Выделите команду ниже и скопируйте вручную.");}}
 function refresh(quiet=false){start(async()=>{const r=await reloadNodeIngressAction(data.node_id);if(r.ok)setData(r.data);if(!quiet||!r.ok)setMessage(r.message);});}
 function save(service:string|null,value:string,revision:number){start(async()=>{const r=await saveNodeIngressAction(data.node_id,service,value,revision);if(r.ok)setData(r.data);setMessage(r.message);});}
 useEffect(()=>{let active=true;const timer=setInterval(()=>{void reloadNodeIngressAction(initial.node_id).then(r=>{if(active&&r.ok)setData(r.data);}).catch(()=>{});},15000);return()=>{active=false;clearInterval(timer);};},[initial.node_id]);
 return <section className="panel node-ingress" aria-label="Резервные входы протоколов">
  <div className="panel-header"><div><h2>Резервные входы протоколов</h2><p>Настройте вход для всей ноды или отдельно для каждого подключения.</p></div><button className="button" disabled={pending} onClick={()=>refresh()}>Обновить состояние</button></div>
  <div className="protocol-form-grid"><label><span>По умолчанию для ноды</span><PolicySelect node policy={data.policy} disabled={pending} save={v=>save(null,v,data.policy.revision)}/></label><div><span>Доступные входы</span><p>{data.entries.filter(e=>e.ready).map(e=>e.name).join(" · ")}</p><Link href="/ingress">Выбрать основной и резервный входы</Link></div></div>
  <p>Новые протоколы автоматически наследуют настройку ноды. Существующие рабочие маршруты на 443 сохраняются. Для остальных подключений входы выделяют отдельный порт; шифрование и авторизация остаются на исходной ноде.</p>
  {data.services.some(s=>!s.supported&&s.protocol!=="pptp")&&<div className="ingress-install"><p>Если агент ноды ещё не сообщает публичный адрес, установите дополнительный компонент. Основной VPN-процесс эта команда не заменяет.</p><button type="button" className="button" onClick={copyInstall}>Скопировать команду установки компонента</button><code className="ingress-install-command">{ingressCompanionInstallCommand()}</code></div>}
  <div className="table-wrap"><table><thead><tr><th>Протокол</th><th>Режим</th><th>Состояние</th></tr></thead><tbody>{data.services.map(s=><tr key={s.id}><td><strong>{s.name}</strong><small style={{display:"block"}}>{s.protocol.toUpperCase()} · {s.transport} · {s.security}</small></td><td><PolicySelect policy={s.policy} disabled={pending||!s.supported} save={v=>save(s.id,v,s.policy.revision)}/></td><td>{!s.enabled?"Протокол выключен":!s.supported?"Нужен публичный адрес агента или поддерживаемый транспорт":s.effective_mode==="enabled"?(s.ready?`Входы готовы · порт ${s.port}`:"Ожидаем подготовки и проверки входов"):s.effective_mode==="direct"?"Напрямую":"Текущий маршрут"}</td></tr>)}</tbody></table></div>
  <p className="protocol-edit-note">Автоматическое переключение доступно в полных конфигурациях Xray, sing-box и Mihomo. Ссылка на один профиль содержит один адрес: в таких подписках добавляется отдельный профиль второго входа. WireGuard и AmneziaWG используют один Endpoint в файле; GRE/PPTP этим входом не поддерживается.</p>
  {message&&<p role="status">{message}</p>}
 </section>;
}
