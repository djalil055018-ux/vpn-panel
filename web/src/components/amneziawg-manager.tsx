"use client";
import { useActionState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import Link from "next/link";
import { amneziaWGAction } from "@/app/amneziawg-actions";
import { AMNEZIAWG_VERSIONS, AMNEZIAWG_COMPATIBILITY } from "@/lib/amneziawg";
import { agentSupportsAmneziaWG } from "@/lib/node-runtime";
import type { VPNServiceRecord, AmneziaWGConfiguration } from "@/lib/control-plane";
import { VPNServiceEditor } from "@/components/vpn-service-editor";

function Submit({children}:{children: ReactNode}) {
  const {pending}=useFormStatus();
  return <button type="submit" className="button primary" disabled={pending}>{pending ? "Сохранение…" : children}</button>;
}
function Form({operation,node="",service="",children}:{operation:string;node?:string;service?:string;children:ReactNode}) {
  const [state,action]=useActionState(amneziaWGAction,{ok:false,message:""});
  return <form action={action} className="plan-form"><input type="hidden" name="operation" value={operation}/><input type="hidden" name="node_id" value={node}/><input type="hidden" name="service_id" value={service}/>{children}{state.message&&<p role="status" className={`plan-feedback ${state.ok?"":"error"}`}>{state.message}</p>}</form>;
}
function VersionSelect({version="2.0"}:{version?:string}) {
  return <label>Версия AmneziaWG<select name="version" defaultValue={version} required>{AMNEZIAWG_VERSIONS.map(v=><option key={v} value={v}>AmneziaWG {v}</option>)}</select></label>;
}
export function AmneziaWGReleaseManager() {
  return <section className="panel"><div className="panel-header"><div><h2>AmneziaWG · пять версий</h2><p>Версии конфигурации 1.0, 1.5, 2.0, 3.0 и 3.1. Для новой отдельной ноды нужен агент 0.2.42+. Подготовьте проверенную сборку в реестре, затем установите ноду.</p></div></div><div className="plan-form"><Form operation="import"><Submit>Добавить проверенную сборку</Submit></Form><Form operation="approve"><Submit>Одобрить проверенную сборку</Submit></Form><Link href="/nodes/new?runtime=amneziawg" className="button">Добавить сервер AmneziaWG</Link></div></section>;
}
export function InitializeAmneziaWG({node,registered}:{node:string;registered:boolean}) {
  return <section className="panel"><div className="panel-header"><div><h2>Подготовить AmneziaWG</h2><p>Начальная конфигурация проверит установленное ядро. Клиентский доступ появится после создания и включения сервиса.</p></div></div><div className="plan-form">{registered?<Form operation="initialize" node={node}><Submit>Отправить начальную конфигурацию</Submit></Form>:<p>Сначала установите агент и дождитесь регистрации.</p>}<Link href="/core-updates" className="button">Реестр сборок</Link></div></section>;
}
export function AmneziaWGServiceManager({node,agentVersion,initialized,services,configurations}:{node:string;agentVersion?:string;initialized:boolean;services:VPNServiceRecord[];configurations:Record<string,AmneziaWGConfiguration|null>}) {
  const supported=initialized&&agentSupportsAmneziaWG(agentVersion);
  return <section id="amneziawg-protocols" className="panel" tabIndex={-1}><div className="panel-header"><div><h2>AmneziaWG</h2><p>Выберите версию для устройств ваших клиентов. Один включённый сервис на отдельной ноде. TCP, UDP и ICMP передаются внутри туннеля; ключи создаются автоматически.</p><p>{AMNEZIAWG_COMPATIBILITY}</p></div></div>
    {supported?<Form operation="create" node={node}><label>Название<input name="name" required maxLength={200} placeholder="Например, Финляндия AmneziaWG"/></label><VersionSelect/><label>Публичный адрес<input name="address" required maxLength={253} placeholder="Домен или IP сервера"/></label><label>UDP-порт<input name="port" type="number" required min={1} max={65535} defaultValue={51820}/></label><Submit>Создать AmneziaWG</Submit></Form>:<p>Нужен агент 0.2.42+ и применённая начальная конфигурация.</p>}
    {services.map(service=><article key={service.id} className="protocol-card"><div className="protocol-card-header"><div><h3>{service.name}</h3><p>AmneziaWG {configurations[service.id]?.version??"· версия не настроена"} · {service.public_address}:{service.public_port} · {service.enabled?"Включён":"Отключён"}</p></div></div><VPNServiceEditor node={node} service={service} agentVersion={agentVersion}/>{supported&&<><Form operation="version" node={node} service={service.id}><VersionSelect version={configurations[service.id]?.version}/><Submit>Сохранить версию</Submit></Form>{(configurations[service.id]||service.enabled)&&<Form operation={service.enabled?"disable":"enable"} node={node} service={service.id}><Submit>{service.enabled?"Отключить":"Включить"} AmneziaWG</Submit></Form>}</>}</article>)}
  </section>;
}
