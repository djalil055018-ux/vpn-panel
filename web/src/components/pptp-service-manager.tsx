"use client";
import { useActionState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { pptpServiceAction } from "@/app/pptp-actions";
import type { VPNServiceRecord } from "@/lib/control-plane";
import { VPNServiceEditor } from "@/components/vpn-service-editor";

function Submit({children}:{children:ReactNode}) {
  const {pending}=useFormStatus();
  return <button className="button primary" disabled={pending}>{pending?"Сохранение…":children}</button>;
}
function Form({node,service="",operation,children}:{node:string;service?:string;operation:string;children:ReactNode}) {
  const [state,action]=useActionState(pptpServiceAction,{ok:false,message:""});
  return <form action={action} className="plan-form"><input type="hidden" name="node_id" value={node}/><input type="hidden" name="service_id" value={service}/><input type="hidden" name="operation" value={operation}/>{children}{state.message&&<p role="status" className={`plan-feedback ${state.ok?"":"error"}`}>{state.message}</p>}</form>;
}
export function PPTPServiceManager({node,initialized,services}:{node:string;initialized:boolean;services:VPNServiceRecord[]}) {
  return <section className="panel">
    <div className="panel-header"><div><h2>PPTP · совместимость</h2><p>Устаревший протокол с известными ограничениями безопасности. Используется MS-CHAPv2 и MPPE128. Для подключения нужны TCP 1723 и GRE (IP-протокол 47); одного открытого TCP-порта недостаточно.</p><p>Выход в интернет по IPv4. IPv6 и внутренние адреса закрыты. Один включённый сервис на ноду, до 252 клиентов и одно подключение на клиента. Логин, пароль и инструкция выдаются в разделе «Клиенты».</p></div></div>
    {initialized?<Form node={node} operation="create"><label>Название<input name="name" required maxLength={200} placeholder="Например, PPTP для старых устройств"/></label><label>Публичный адрес<input name="address" required maxLength={253} placeholder="Домен с IPv4 или IPv4-адрес"/></label><p>TCP 1723 + GRE · MPPE128</p><Submit>Создать PPTP</Submit></Form>:<p>Сначала отправьте начальную конфигурацию на ноду.</p>}
    {services.map(service=><article className="protocol-card" key={service.id}><div className="protocol-card-header"><div><h3>{service.name}</h3><p>PPTP · {service.public_address}:1723 + GRE · {service.enabled?"Включён":"Отключён"}</p></div></div><VPNServiceEditor node={node} service={service} /><Form node={node} service={service.id} operation={service.enabled?"disable":"enable"}><Submit>{service.enabled?"Отключить PPTP":"Включить PPTP"}</Submit></Form></article>)}
  </section>;
}
