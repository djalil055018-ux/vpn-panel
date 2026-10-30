"use client";
import {useActionState,type ReactNode} from "react";
import {useFormStatus} from "react-dom";
import {openvpnServiceAction} from "@/app/openvpn-actions";
import type {VPNServiceRecord} from "@/lib/control-plane";
import { VPNServiceEditor } from "@/components/vpn-service-editor";
function Submit({children}:{children:ReactNode}) {const {pending}=useFormStatus();return <button className="button primary" disabled={pending}>{pending?"Сохранение…":children}</button>;}
function Form({node,service="",operation,children}:{node:string;service?:string;operation:string;children:ReactNode}) {
  const [state,action]=useActionState(openvpnServiceAction,{ok:false,message:""});
  return <form action={action} className="plan-form"><input type="hidden" name="node_id" value={node}/><input type="hidden" name="service_id" value={service}/><input type="hidden" name="operation" value={operation}/>{children}{state.message&&<p role="status" className={`plan-feedback ${state.ok?"":"error"}`}>{state.message}</p>}</form>;
}
export function OpenVPNServiceManager({node,initialized,services}:{node:string;initialized:boolean;services:VPNServiceRecord[]}) {
  return <section className="panel"><div className="panel-header"><div><h2>OpenVPN</h2><p>Стандартный профиль .ovpn для OpenVPN Connect и совместимых клиентов. Сертификаты создаются автоматически. Выход в интернет по IPv4; IPv6 и доступ к внутренним адресам закрыты. На ноде может быть включён один сервис, до 252 клиентов.</p></div></div>
    {initialized?<Form node={node} operation="create"><label>Название<input name="name" required maxLength={200} placeholder="Например, Sweden OpenVPN"/></label><label>Публичный адрес<input name="address" required placeholder="Домен или IP ноды"/></label><label>Транспорт<select name="transport" defaultValue="udp"><option value="udp">UDP</option><option value="tcp">TCP</option></select></label><label>Порт<input name="port" type="number" min={1} max={65535} required defaultValue={1194}/></label><Submit>Создать OpenVPN</Submit></Form>:<p>Сначала отправьте начальную конфигурацию на ноду.</p>}
    {services.map(service=><article className="protocol-card" key={service.id}><div className="protocol-card-header"><div><h3>{service.name}</h3><p>OpenVPN · {service.transport.toUpperCase()} · {service.public_address}:{service.public_port} · {service.enabled?"Включён":"Отключён"}</p></div></div><VPNServiceEditor node={node} service={service} /><Form node={node} service={service.id} operation={service.enabled?"disable":"enable"}><Submit>{service.enabled?"Отключить OpenVPN":"Включить OpenVPN"}</Submit></Form></article>)}
  </section>;
}
