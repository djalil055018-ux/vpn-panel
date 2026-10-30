"use client";

import { useActionState } from "react";
import { useFormStatus } from "react-dom";
import { updateVPNServiceSettingsAction } from "@/app/vpn-service-actions";
import { agentSupportsVLESSTLS, agentSupportsVLESSXHTTP, agentSupportsWebTransports, xraySupportsXHTTP } from "@/lib/node-runtime";
import { VPNServiceDelete } from "@/components/vpn-service-delete";
import type { VPNServiceRecord } from "@/lib/control-plane";

const initialState = { ok: true, message: "" };

function SaveButton() {
  const { pending } = useFormStatus();
  return <button type="submit" className="button primary" disabled={pending}>{pending ? "Сохраняем…" : "Сохранить конфигурацию"}</button>;
}

export function VPNServiceEditor({ node, service, agentVersion, coreVersion }: { node: string; service: VPNServiceRecord; agentVersion?: string; coreVersion?: string | null }) {
  const [state, action] = useActionState(updateVPNServiceSettingsAction, initialState);
  const canUseVLESSTLS = agentSupportsVLESSTLS(agentVersion);
  const canUseWebTransports = agentSupportsWebTransports(agentVersion);
  const canUseXHTTP = agentSupportsVLESSXHTTP(agentVersion) && xraySupportsXHTTP(coreVersion);

  return <details className="protocol-edit">
    <summary>Изменить конфигурацию</summary>
    <form action={action} className="protocol-form">
      <input type="hidden" name="node_id" value={node} />
      <input type="hidden" name="service_id" value={service.id} />
      <div className="protocol-form-grid">
        <label><span>Название</span><input name="name" required maxLength={200} defaultValue={service.name} /></label>
        <label><span>Адрес прослушивания на сервере</span><input name="listen" required maxLength={45} defaultValue={service.listen} placeholder="0.0.0.0 или адрес интерфейса" /></label>
        {service.protocol === "pptp" ? <label><span>Порт на сервере</span><input value="1723 (фиксированный для PPTP)" readOnly /><input type="hidden" name="port" value="1723" /></label> : <label><span>Порт на сервере</span><input name="port" type="number" min={1} max={65535} required defaultValue={service.port} /></label>}
        {service.protocol === "openvpn" ? <label><span>Транспорт OpenVPN</span><select name="transport" defaultValue={service.transport}><option value="udp">UDP</option><option value="tcp">TCP</option></select></label> : service.protocol === "vless" && service.security === "tls" ? <label><span>Транспорт VLESS TLS</span><select name="transport" defaultValue={service.transport}><option value="tcp" disabled={!canUseVLESSTLS && service.transport !== "tcp"}>TCP{!canUseVLESSTLS && service.transport !== "tcp" ? " — agent ≥0.2.15" : ""}</option><option value="xhttp" disabled={!canUseXHTTP && service.transport !== "xhttp"}>XHTTP{!canUseXHTTP && service.transport !== "xhttp" ? (!agentSupportsVLESSXHTTP(agentVersion) ? " — требуется агент 0.2.17" : " — требуется Xray 26.7.28") : ""}</option><option value="ws" disabled={!canUseWebTransports && service.transport !== "ws"}>WebSocket{!canUseWebTransports && service.transport !== "ws" ? " — обновите агент до 0.2.26" : ""}</option><option value="grpc" disabled={!canUseWebTransports && service.transport !== "grpc"}>gRPC{!canUseWebTransports && service.transport !== "grpc" ? " — обновите агент до 0.2.26" : ""}</option></select></label> : <input type="hidden" name="transport" value={service.transport} />}
        <label><span>Публичный адрес</span><input name="public_address" required maxLength={253} defaultValue={service.public_address ?? ""} placeholder="Домен или IP" /></label>
        {service.protocol === "pptp" ? <input type="hidden" name="public_port" value="1723" /> : <label><span>Порт в подписке</span><input name="public_port" type="number" min={1} max={65535} required defaultValue={service.public_port ?? service.port} /></label>}
      </div>
      <p className="protocol-edit-note">Адрес прослушивания должен быть назначен сетевому интерфейсу узла; 0.0.0.0 принимает соединения на всех IPv4 интерфейсах. Новая генерация применится агентом узла. Если публичный адрес или порт отличается от внутреннего, настройте DNS, firewall и перенаправление на сервере. Для OpenVPN изменяется транспорт TCP/UDP и профиль клиента сформируется с новым значением.</p>
      {service.protocol === "vless" && service.security === "tls" && <p className="protocol-edit-note">Транспорт меняет формат профиля в подписке. После применения обновите подписку в приложениях клиентов. XHTTP требует агент 0.2.17+ и Xray 26.7.28+, WebSocket и gRPC — агента 0.2.26+.</p>}
      <div className="protocol-form-actions"><SaveButton /></div>
    </form>
    {state.message && <p role="status" className={`protocol-result ${state.ok ? "success" : "error"}`}>{state.message}</p>}
    <VPNServiceDelete serviceID={service.id} name={service.name} />
  </details>;
}
