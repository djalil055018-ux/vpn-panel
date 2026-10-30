"use client";
import { useActionState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { wireguardServiceAction } from "@/app/wireguard-actions";
import { agentSupportsWebTransports, agentSupportsNativeWireGuard } from "@/lib/node-runtime";
import type { VPNServiceRecord } from "@/lib/control-plane";
import { VPNServiceEditor } from "@/components/vpn-service-editor";

function Submit({ children }: { children: ReactNode }) {
  const { pending } = useFormStatus();
  return <button className="button primary" disabled={pending}>{pending ? "Сохранение…" : children}</button>;
}
function Form({ node, service = "", operation, children }: { node: string; service?: string; operation: string; children: ReactNode }) {
  const [state, action] = useActionState(wireguardServiceAction, { ok: false, message: "" });
  return <form action={action} className="plan-form"><input type="hidden" name="node_id" value={node} /><input type="hidden" name="service_id" value={service} /><input type="hidden" name="operation" value={operation} />{children}{state.message && <p role="status" className={`plan-feedback ${state.ok ? "" : "error"}`}>{state.message}</p>}</form>;
}
export function WireGuardServiceManager({ node, agentVersion, services, native = false, initialized = true }: { node: string; agentVersion?: string; services: VPNServiceRecord[]; native?: boolean; initialized?: boolean }) {
  const supported = initialized && (native ? agentSupportsNativeWireGuard(agentVersion) : agentSupportsWebTransports(agentVersion));
  return <section id="wireguard-protocols" tabIndex={-1} className="panel"><div className="panel-header"><div><h2>{native ? "WireGuard Native" : "WireGuard"}</h2><p>Стандартный профиль .conf и QR-код для клиента WireGuard. {native ? "Отдельная нода с поддержкой TCP, UDP и ICMP. Одновременно можно включить один сервис. Доступ к внутренним адресам ноды закрыт." : "На этой ноде поддерживается трафик TCP и UDP; ICMP не поддерживается."} Ключи и адреса создаются автоматически.</p></div></div>
    {supported ? <Form node={node} operation="create"><label>Название<input name="name" required maxLength={200} placeholder="Например, Sweden WireGuard" /></label><label>Публичный адрес<input name="address" required placeholder="Домен или IP ноды" /></label><label>UDP-порт<input name="port" type="number" min={1} max={65535} required defaultValue={51820} /></label><Submit>Создать WireGuard</Submit></Form> : <p>{native ? "Для новых нод используйте Agent 0.2.29. Минимум совместимости — 0.2.28; также требуется начальная конфигурация WireGuard Native." : "Для WireGuard требуется агент 0.2.26 или новее."}</p>}
    {services.map(service => <article className="protocol-card" key={service.id}><div className="protocol-card-header"><div><h3>{service.name}</h3><p>{native ? "WireGuard Native" : "WireGuard через Xray"} · {service.public_address}:{service.public_port} · {service.enabled ? "Включён" : "Отключён"}</p></div></div><VPNServiceEditor node={node} service={service} />{supported && <Form node={node} service={service.id} operation={service.enabled ? "disable" : "enable"}><Submit>{service.enabled ? "Отключить WireGuard" : "Включить WireGuard"}</Submit></Form>}</article>)}
  </section>;
}

