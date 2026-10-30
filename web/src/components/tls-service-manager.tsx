"use client";
import { useActionState, type ReactNode } from "react";
import { useFormStatus } from "react-dom";
import { tlsServiceAction } from "@/app/tls-actions";
import type { VPNServiceRecord, VPNServiceTLS } from "@/lib/control-plane";
import { VPNServiceEditor } from "@/components/vpn-service-editor";
import { agentSupportsWebTransports, type NodeRuntime } from "@/lib/node-runtime";
type Certificate = { id: string; domain: string };
function Submit({ children }: { children: ReactNode }) { const { pending } = useFormStatus(); return <button className="button primary" disabled={pending}>{pending ? "Сохранение…" : children}</button>; }
function Form({ node, service = "", operation, children }: { node: string; service?: string; operation: string; children: ReactNode }) {
  const [state, action] = useActionState(tlsServiceAction, { ok: false, message: "" });
  return <form action={action} className="plan-form"><input type="hidden" name="node_id" value={node} /><input type="hidden" name="service_id" value={service} /><input type="hidden" name="operation" value={operation} />{children}{state.message && <p role="status" className={`plan-feedback ${state.ok ? "" : "error"}`}>{state.message}</p>}</form>;
}
function CertificateSelect({ certificates, selected }: { certificates: Certificate[]; selected?: string }) {
  return <label>Сертификат<select name="certificate_id" required defaultValue={selected ?? ""}><option value="" disabled>Выберите домен</option>{certificates.map(c => <option key={c.id} value={c.id}>{c.domain}</option>)}</select></label>;
}
export function TLSServiceManager({ node, runtime, services, certificates, configurations, agentVersion, coreVersion }: { agentVersion?: string; coreVersion?: string | null; node: string; runtime: NodeRuntime; services: VPNServiceRecord[]; certificates: Certificate[]; configurations: Record<string, VPNServiceTLS | null> }) {
  const webTransports = agentSupportsWebTransports(agentVersion);
  const hysteria = runtime === "hysteria2";
  const activeListener = hysteria && services.some(s => s.enabled);
  return <section id="tls-protocols" tabIndex={-1} className="panel"><div className="panel-header"><div><h2>{hysteria ? "Hysteria 2 с TLS" : "Протоколы с TLS"}</h2><p>{hysteria ? "Соединения по UDP с сертификатом вашего домена. На ноде может быть включён один сервис Hysteria; остальные можно сохранить как черновики. Для версии 2.13.0 требуется агент 0.2.43 или новее; для действующих нод с 2.12.2 — 0.2.25+." : "Подключения с сертификатом вашего домена. VLESS: агент 0.2.15+, Trojan: 0.2.16+, VLESS XHTTP: 0.2.17+, WebSocket и gRPC: 0.2.26+."}</p></div></div>
    {certificates.length ? <Form node={node} operation="create"><label>Протокол<select name="protocol" defaultValue={hysteria ? "hysteria2" : "vless"}>{hysteria ? <option value="hysteria2">Hysteria 2 · UDP · TLS</option> : <><option value="vless">VLESS TLS</option><option value="trojan">Trojan TLS</option><option value="vless-xhttp">VLESS XHTTP TLS</option><option value="vless-ws" disabled={!webTransports}>VLESS WebSocket TLS{webTransports ? "" : " — требуется обновление агента"}</option><option value="vless-grpc" disabled={!webTransports}>VLESS gRPC TLS{webTransports ? "" : " — требуется обновление агента"}</option></>}</select></label><label>Название<input name="name" required maxLength={200} placeholder={hysteria ? "Например, Sweden Hysteria" : "Например, Sweden TLS"} /></label><label>{hysteria ? "UDP-порт" : "Порт"}<input name="port" type="number" min={1} max={65535} required defaultValue={hysteria ? 443 : 8443} /></label><CertificateSelect certificates={certificates} /><Submit>Создать TLS-сервис</Submit></Form> : <p className="certificate-note">Сначала выпустите production-сертификат этой ноды в разделе «Сертификаты».</p>}
    {services.map(s => <article className="protocol-card" key={s.id}><div className="protocol-card-header"><div><h3>{s.name}</h3><p>{s.protocol === "hysteria2" ? "Hysteria 2 · UDP · TLS" : ["xhttp", "ws", "grpc"].includes(s.transport) ? `VLESS ${s.transport.toUpperCase()} TLS` : s.protocol === "trojan" ? "Trojan TLS" : "VLESS TLS"} · {s.public_address}:{s.public_port} · {s.enabled ? "Включён" : "Отключён"}</p><p>Сертификат: {configurations[s.id]?.server_name ?? "Не выбран"}</p></div></div>
      <VPNServiceEditor node={node} service={s} agentVersion={agentVersion} coreVersion={coreVersion} />
      {certificates.length > 0 && <Form node={node} service={s.id} operation="certificate"><CertificateSelect certificates={certificates} selected={configurations[s.id]?.certificate_id} /><Submit>Сохранить сертификат</Submit></Form>}
      {activeListener && !s.enabled ? <p className="certificate-note">Для включения этого сервиса сначала отключите текущий сервис Hysteria.</p> : <Form node={node} service={s.id} operation={s.enabled ? "disable" : "enable"}><Submit>{s.enabled ? "Отключить TLS-сервис" : "Включить TLS-сервис"}</Submit></Form>}
    </article>)}
  </section>;
}
