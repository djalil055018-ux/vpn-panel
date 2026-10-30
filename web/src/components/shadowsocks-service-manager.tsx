"use client";
import { useActionState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { shadowsocksServiceAction } from "@/app/shadowsocks-actions";
import { agentSupportsWebTransports } from "@/lib/node-runtime";
import type { VPNServiceRecord } from "@/lib/control-plane";
import { VPNServiceEditor } from "@/components/vpn-service-editor";

function Submit({ children }: { children: ReactNode }) {
  const { pending } = useFormStatus();
  return <button className="button primary" disabled={pending}>{pending ? "Сохранение…" : children}</button>;
}
function Form({ node, service = "", operation, children }: { node: string; service?: string; operation: string; children: ReactNode }) {
  const [state, action] = useActionState(shadowsocksServiceAction, { ok: false, message: "" });
  return <form action={action} className="plan-form"><input type="hidden" name="node_id" value={node} /><input type="hidden" name="service_id" value={service} /><input type="hidden" name="operation" value={operation} />{children}{state.message && <p role="status" className={`plan-feedback ${state.ok ? "" : "error"}`}>{state.message}</p>}</form>;
}
export function ShadowsocksServiceManager({ node, agentVersion, services }: { node: string; agentVersion?: string; services: VPNServiceRecord[] }) {
  const supported = agentSupportsWebTransports(agentVersion);
  return <section id="shadowsocks-protocols" tabIndex={-1} className="panel"><div className="panel-header"><div><h2>Shadowsocks 2022</h2><p>TCP и UDP, шифрование AES-256-GCM. Сертификат не требуется. Ключи клиентов создаются автоматически. Без назначенных клиентов порт закрыт.</p></div></div>
    {supported ? <Form node={node} operation="create"><label>Название<input name="name" required maxLength={200} placeholder="Например, Sweden Shadowsocks" /></label><label>Публичный адрес<input name="address" required placeholder="Домен или IP ноды" /></label><label>Порт TCP и UDP<input name="port" type="number" min={1} max={65535} required defaultValue={8388} /></label><Submit>Создать Shadowsocks</Submit></Form> : <p>Для Shadowsocks требуется агент 0.2.26 или новее.</p>}
    {services.map(service => <article className="protocol-card" key={service.id}><div className="protocol-card-header"><div><h3>{service.name}</h3><p>Shadowsocks 2022 · {service.public_address}:{service.public_port} · {service.enabled ? "Включён" : "Отключён"}</p></div></div><VPNServiceEditor node={node} service={service} />{supported && <Form node={node} service={service.id} operation={service.enabled ? "disable" : "enable"}><Submit>{service.enabled ? "Отключить Shadowsocks" : "Включить Shadowsocks"}</Submit></Form>}</article>)}
  </section>;
}
