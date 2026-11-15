"use client";
import Link from "next/link";
import { useEffect, useState, useTransition } from "react";
import type { ProtocolTemplate, TemplateApplication, TemplatePreview, TemplateTarget } from "@/lib/protocol-templates";
import { templateTargetsAction, templatePreviewAction, templateApplyAction, templateStatusAction } from "@/app/protocol-template-actions";
const reasonLabels:Record<string,string>={
 runtime:"Шаблон требует другое ядро. Выберите совместимый сервер или добавьте новый.",
 not_registered:"Сначала установите агент на сервер.", agent_update:"Обновите агент сервера до версии 0.2.45 или новее.",
 initialize:"Отправьте начальную конфигурацию через Control Center.", busy:"Дождитесь применения текущей конфигурации сервера.",
 offline:"Нет свежего подтверждения исправности сервера.", imported_profile:"Импортированный профиль управляется через отдельный процесс переноса.",
 dedicated_listener:"На этом ядре уже включён сервис. Для отдельного варианта нужен свободный сервер либо отключение текущего сервиса.",
 core_update:"Обновите ядро до совместимой версии: Xray 26.10.21+ или Hysteria 2.13.0.", core_release:"Активная сборка ядра должна быть одобрена в панели.", stale:"Состояние сервера изменилось. Повторите проверку.",
 certificate:"Выберите действующий production-сертификат этого сервера.", plan:"Выбранная группа недоступна этому серверу.",
 port:"Этот порт занят другим сервисом панели. Выберите свободный порт.",
};
const statusLabels:Record<string,string>={pending:"Ожидаем сервер",applying:"Сервер применяет конфигурацию",applied:"Сервис применён",failed:"Применение завершилось ошибкой",rolled_back:"Агент выполнил откат",disabled:"Сервис отключён",deleted:"Сервис удалён"};
const terminal=new Set(["applied","failed","rolled_back","disabled","deleted"]);
export function ProtocolTemplateApply({template,initialInstallation=""}:{template:ProtocolTemplate;initialInstallation?:string}) {
 const [targets,setTargets]=useState<TemplateTarget[]>([]);
 const [node,setNode]=useState("");
 const [name,setName]=useState(template.name);
 const [address,setAddress]=useState("");
 const [port,setPort]=useState(String(template.default_port));
 const [certificate,setCertificate]=useState("");
 const [serverName,setServerName]=useState("");
 const [realityTarget,setRealityTarget]=useState("");
 const [plans,setPlans]=useState<string[]>([]);
 const [preview,setPreview]=useState<TemplatePreview|null>(null);
 const [receipt,setReceipt]=useState<TemplateApplication|null>(null);
 const [message,setMessage]=useState("");
 const [pending,startTransition]=useTransition();
 const selected=targets.find(t=>t.node_id===node);
 const reality=template.security==="reality";
 const needsCertificate=template.security==="tls"&&template.protocol!=="openvpn";
 async function refreshTargets() {try{const r=await templateTargetsAction(template.id);if(r.ok)setTargets(r.value.targets);else setMessage(r.message);}catch{setMessage("Не удалось загрузить серверы. Обновите страницу после восстановления сети.");}}
 useEffect(()=>{let alive=true;templateTargetsAction(template.id).then(r=>{if(!alive)return;if(r.ok)setTargets(r.value.targets);else setMessage(r.message);}).catch(()=>{if(alive)setMessage("Не удалось загрузить серверы. Обновите страницу после восстановления сети.");});return()=>{alive=false;};},[template.id]);
 useEffect(()=>{
  if(!initialInstallation)return;
  let alive=true;templateStatusAction(initialInstallation).then(r=>{if(!alive)return;if(r.ok&&r.value.template_id===template.id)setReceipt(r.value);else setMessage("Сохранённый запрос недоступен. Проверьте состояние сервера.");}).catch(()=>{if(alive)setMessage("Не удалось восстановить статус запроса. Обновите страницу после восстановления сети.");});
  return()=>{alive=false;};
 },[initialInstallation,template.id]);
 useEffect(()=>{
  if(!receipt||terminal.has(receipt.status))return;
  let alive=true,loading=false;
  const timer=setInterval(()=>{if(loading)return;loading=true;templateStatusAction(receipt.request_key).then(r=>{if(alive&&r.ok){setReceipt(r.value);setMessage("");}}).catch(()=>{if(alive)setMessage("Связь с панелью прервалась. Проверка продолжится после восстановления сети.");}).finally(()=>{loading=false;});},3000);
  return()=>{alive=false;clearInterval(timer);};
 },[receipt?.request_key,receipt?.status]);
 function changed(){setPreview(null);setMessage("");}
 function choose(id:string){
  changed();setNode(id);setPlans([]);
  const t=targets.find(t=>t.node_id===id);
  if(t){setName(template.name+" · "+t.name);setAddress(t.public_address);setPort(String(t.suggested_port||template.default_port));setCertificate(t.certificates[0]?.id||"");setServerName(t.server_name);setRealityTarget(t.reality_target);}
 }
 async function check(){
  try {
  setMessage("");setPreview(null);
  const r=await templatePreviewAction(template.id,{node_id:node,name,public_address:address,port:Number(port),certificate_id:needsCertificate?certificate:"",server_name:reality?serverName:"",reality_target:reality?realityTarget:"",plan_ids:plans,request_key:crypto.randomUUID(),expected_generation:0,revision:""});
  if(r.ok)setPreview(r.value);else setMessage(r.message);
  }catch{setMessage("Проверка недоступна. Повторите после восстановления сети.");}
 }
 async function apply(){
  if(!preview?.ready)return;
  try {
  setMessage("");
  const r=await templateApplyAction(template.id,preview.input);
  if(r.ok){
   setReceipt(r.value);
   window.history.replaceState(null,"","/protocol-templates?template="+encodeURIComponent(template.id)+"&installation="+encodeURIComponent(r.value.request_key));
  }else{
   const status=await templateStatusAction(preview.input.request_key);
   if(status.ok)setReceipt(status.value);else setMessage(r.message);
  }
  }catch{setMessage("Ответ не получен. Повторное применение проверит тот же запрос и не создаст дубликат.");}
 }
 if(template.legacy)return null;
 if(receipt)return <section className="template-apply" aria-label="Результат применения"><h3>{statusLabels[receipt.status]||"Проверяем состояние"}</h3><p>Поколение конфигурации: {receipt.generation}.</p>{receipt.status==="applied"?<p>Сервер подтвердил применение. Обновите подписку клиентов выбранных групп. Дополнительный доступ можно назначить в разделе «Группы доступа».</p>:terminal.has(receipt.status)?<p>Откройте Control Center и проверьте сервис. После ошибки отключите или удалите неприменённый вариант перед новым запуском.</p>:<p>Панель ожидает подтверждение агента. Статус обновляется автоматически.</p>}<div className="template-file-actions"><Link className="button" href={"/nodes/"+receipt.node_id+"/control"}>Открыть сервер</Link>{terminal.has(receipt.status)&&<button type="button" className="button" onClick={()=>{setReceipt(null);setPreview(null);setMessage("");window.history.replaceState(null,"","/protocol-templates?template="+encodeURIComponent(template.id));void refreshTargets();}}>Добавить другой вариант</button>}</div></section>;
 return <section className="template-apply" aria-label="Применение шаблона"><h3>Добавить на сервер</h3><p>Будет создан отдельный сервис с ключами и настройками своей установки. Для Hysteria, WireGuard Native, AmneziaWG и OpenVPN выберите сервер с соответствующим ядром.</p>
 <form onSubmit={e=>{e.preventDefault();startTransition(check);}} className="template-apply-form"><fieldset disabled={pending}><label>Сервер<select required value={node} onChange={e=>choose(e.target.value)}><option value="">Выберите сервер</option>{targets.filter(t=>t.runtime===template.runtime).map(t=><option key={t.node_id} value={t.node_id}>{t.name}{t.ready?"":" · требуется подготовка"}</option>)}</select></label>
 {!targets.some(t=>t.runtime===template.runtime)&&<p>Совместимых серверов пока нет. <Link href={"/nodes/new?runtime="+encodeURIComponent(template.runtime)}>Добавить сервер</Link></p>}
 {selected&&<><p className="template-help">Агент {selected.agent||"не установлен"} · ядро {selected.core_version||"не настроено"}</p>{selected.reasons?.length>0&&<div role="status"><ul>{selected.reasons.map(code=><li key={code}>{reasonLabels[code]||"Требуется подготовка сервера."}</li>)}</ul>{selected.reasons.includes("agent_update")&&<Link className="button" href="/agent-updates">Обновления агентов</Link>}<Link className="button" href={"/nodes/"+node+"/control"}>Control Center</Link></div>}
 <label>Название сервиса<input required maxLength={200} value={name} onChange={e=>{changed();setName(e.target.value);}}/></label><label>Публичный IP или домен<input required maxLength={253} value={address} onChange={e=>{changed();setAddress(e.target.value);}}/></label><label>{template.transport==="udp"?"UDP-порт":"Порт"}<input required type="number" min={1} max={65535} value={port} onChange={e=>{changed();setPort(e.target.value);}}/></label>
 {needsCertificate&&<label>Сертификат<select required value={certificate} onChange={e=>{changed();setCertificate(e.target.value);}}><option value="">Выберите сертификат</option>{selected.certificates.map(c=><option key={c.id} value={c.id}>{c.name}</option>)}</select>{!selected.certificates.length&&<Link href="/certificates">Выпустить сертификат</Link>}</label>}
 {reality&&<><label>Домен REALITY (SNI)<input required maxLength={253} value={serverName} onChange={e=>{changed();setServerName(e.target.value);}}/></label><label>Целевой сервер REALITY: домен и порт<input required maxLength={320} placeholder="example.com:443" value={realityTarget} onChange={e=>{changed();setRealityTarget(e.target.value);}}/></label><p className="template-help">Цель должна поддерживать TLS 1.3 и HTTP/2, а SNI — соответствовать её сертификату.</p></>}
 <fieldset className="template-plan-choices"><legend>Группы доступа</legend>{selected.plans.map(plan=><label key={plan.id}><input type="checkbox" checked={plans.includes(plan.id)} onChange={e=>{changed();setPlans(e.target.checked?[...plans,plan.id]:plans.filter(p=>p!==plan.id));}}/>{plan.name}</label>)}{!plans.length&&<p>Без выбора групп сервис будет создан без доступа для клиентов. Назначить доступ можно позже.</p>}</fieldset>
 <p className="template-help">Квоты трафика и ограничения скорости в шаблоне отсутствуют. Действующие тарифы и права клиентов учитываются панелью.</p>
 <button className="button" type="submit" disabled={!selected.ready}>Проверить перед применением</button></>}</fieldset></form>
 {preview&&<section className="template-preview" aria-label="Предварительная проверка"><h4>{preview.ready?"Готово к применению":"Требуется исправить"}</h4>{preview.ready?<><dl><dt>Сервер</dt><dd>{preview.target.name}</dd><dt>Сервис</dt><dd>{preview.input.name}</dd><dt>Адрес</dt><dd>{preview.input.public_address}:{preview.input.port}</dd><dt>Групп доступа</dt><dd>{preview.input.plan_ids.length}</dd></dl><p>Панель проверила совместимость, сертификат и занятость порта своими сервисами. Агент проверит и применит конфигурацию на сервере. Профиль появится в подписках после подтверждения.</p><button type="button" className="button primary" disabled={pending} onClick={()=>startTransition(apply)}>Применить на сервере</button></>:<ul>{preview.reasons.map(code=><li key={code}>{reasonLabels[code]||"Повторите проверку сервера."}</li>)}</ul>}</section>}
 <p role="status" aria-live="polite">{pending?"Выполняем запрос…":message}</p></section>;
}
