"use client";
import Link from "next/link";

import {
  useActionState,
} from "react";

import {
  useFormStatus,
} from "react-dom";

import {
  createVLESSRealityServiceAction,
  toggleVPNServiceAction,
  updateRealityServiceAction,
  type ProtocolActionState,
} from "@/app/protocol-actions";

import type {
  VPNServiceRealityRecord,
  VPNServiceRecord,
} from "@/lib/control-plane";

import { agentSupportsWebTransports } from "@/lib/node-runtime";
import { VPNServiceEditor } from "@/components/vpn-service-editor";

const initialState:
  ProtocolActionState = {
    ok: true,
    message: "",
  };

function ActionMessage({
  state,
}: {
  state:
    ProtocolActionState;
}) {
  if (!state.message) {
    return null;
  }

  return (
    <div
      className={
        state.ok
          ? "protocol-result success"
          : "protocol-result error"
      }
    >
      {state.message}
    </div>
  );
}

function SubmitButton({
  children,
  variant = "primary",
}: {
  children:
    React.ReactNode;
  variant?:
    "primary" |
    "ghost" |
    "danger";
}) {
  const {
    pending,
  } =
    useFormStatus();

  return (
    <button
      type="submit"
      className={
        `button ${variant}`
      }
      disabled={pending}
    >
      {pending
        ? "Применяем..."
        : children}
    </button>
  );
}

function ServiceCard({
  nodeID,
  service,
  reality,
}: {
  nodeID: string;

  service:
    VPNServiceRecord;
  reality:
    VPNServiceRealityRecord |
    null;
}) {
  const [
    updateState,
    updateAction,
  ] =
    useActionState(
      updateRealityServiceAction,
      initialState
    );

  const [
    toggleState,
    toggleAction,
  ] =
    useActionState(
      toggleVPNServiceAction,
      initialState
    );

  const supported =
    service.protocol ===
      "vless" &&
    service.transport ===
      "tcp" &&
    service.security ===
      "reality";

  return (
    <article className="protocol-card">
      <div className="protocol-card-header">
        <div>
          <div className="protocol-title">
            <strong>
              {service.name}
            </strong>

            <span
              className={
                service.enabled
                  ? "status success"
                  : "status warning"
              }
            >
              <span
                className="status-dot"
                aria-hidden="true"
              />

              {service.enabled
                ? "Включён"
                : "Отключён"}
            </span>
          </div>

          <p>
            {service.protocol.toUpperCase()}
            {" · "}
            {service.transport.toUpperCase()}
            {" · "}
            {service.security.toUpperCase()}
          </p>
        </div>

        <span
          className={
            supported
              ? "protocol-capability ready"
              : "protocol-capability pending"
          }
        >
          {supported
            ? "Поддерживается"
            : "Driver не готов"}
        </span>
      </div>

      <dl className="protocol-detail-grid">
        <div>
          <dt>
            Listen
          </dt>
          <dd>
            {service.listen}
            :
            {service.port}
          </dd>
        </div>

        <div>
          <dt>
            Публичный адрес
          </dt>
          <dd>
            {service.public_address &&
            service.public_port
              ? `${service.public_address}:${service.public_port}`
              : "Не задан"}
          </dd>
        </div>

        <div>
          <dt>
            Target
          </dt>
          <dd>
            {reality?.destination ??
              "—"}
          </dd>
        </div>

        <div>
          <dt>
            SNI
          </dt>
          <dd>
            {reality?.server_name ??
              "—"}
          </dd>
        </div>

        <div>
          <dt>
            Fingerprint
          </dt>
          <dd>
            {reality?.fingerprint ??
              "—"}
          </dd>
        </div>

        <div>
          <dt>
            Short ID
          </dt>
          <dd>
            {reality?.short_id
              ? "Создан"
              : "—"}
          </dd>
        </div>
      </dl>

      <VPNServiceEditor node={nodeID} service={service} />

      {supported &&
        reality && (
          <details className="protocol-edit">
            <summary>
              Изменить REALITY
            </summary>

            <form
              action={updateAction}
              className="protocol-form"
            >
              <input
                type="hidden"
                name="node_id"
                value={nodeID}
              />

              <input
                type="hidden"
                name="service_id"
                value={service.id}
              />

              <input
                type="hidden"
                name="enabled"
                value={
                  service.enabled
                    ? "true"
                    : "false"
                }
              />

              <label>
                <span>
                  Target
                </span>

                <input
                  name="destination"
                  required
                  defaultValue={
                    reality.destination
                  }
                />
              </label>

              <label>
                <span>
                  SNI
                </span>

                <input
                  name="server_name"
                  required
                  defaultValue={
                    reality.server_name
                  }
                />
              </label>

              <label>
                <span>
                  Fingerprint
                </span>

                <select
                  name="fingerprint"
                  defaultValue={
                    reality.fingerprint ||
                    "chrome"
                  }
                >
                  <option value="chrome">
                    Chrome
                  </option>
                  <option value="firefox">
                    Firefox
                  </option>
                  <option value="edge">
                    Edge
                  </option>
                  <option value="safari">
                    Safari
                  </option>
                  <option value="ios">
                    iOS
                  </option>
                  <option value="android">
                    Android
                  </option>
                  <option value="random">
                    Random
                  </option>
                </select>
              </label>

              <div className="protocol-form-actions">
                <SubmitButton>
                  Сохранить и применить
                </SubmitButton>
              </div>
            </form>

            <ActionMessage
              state={updateState}
            />
          </details>
        )}

      {supported && (
        <form
          action={toggleAction}
          className="protocol-toggle"
          onSubmit={(event) => {
            if (
              service.enabled &&
              !window.confirm(
                "Отключить VPN-сервис? Он исчезнет из активных конфигураций и подписок клиентов после применения нового поколения."
              )
            ) {
              event.preventDefault();
            }
          }}
        >
          <input
            type="hidden"
            name="node_id"
            value={nodeID}
          />

          <input
            type="hidden"
            name="service_id"
            value={service.id}
          />

          <input
            type="hidden"
            name="operation"
            value={
              service.enabled
                ? "disable"
                : "enable"
            }
          />

          <SubmitButton
            variant={
              service.enabled
                ? "danger"
                : "primary"
            }
          >
            {service.enabled
              ? "Отключить сервис"
              : "Включить сервис"}
          </SubmitButton>
        </form>
      )}

      <ActionMessage
        state={toggleState}
      />
    </article>
  );
}

export function ProtocolManager({
  nodeID,
  agentVersion,
  services,
  realities,
}: {
  nodeID: string;
  agentVersion?: string;
  services:
    VPNServiceRecord[];
  realities:
    Record<
      string,
      VPNServiceRealityRecord |
      null
    >;
}) {
  const [
    createState,
    createAction,
  ] =
    useActionState(
      createVLESSRealityServiceAction,
      initialState
    );

  return (
    <section className="protocol-manager">
      <div className="protocol-manager-header">
        <div>
          <div className="eyebrow">
            ПРОТОКОЛЫ
          </div>

          <h2>
            VLESS REALITY
          </h2>

          <p>
            VPN-сервисы ноды управляются через
            Control Plane и применяются Node Agent.
          </p>
        </div>

        <span className="protocol-manager-count">
          {services.length}
        </span>
      </div>

      <div className="protocol-list">
        {services.map(
          (service) => (
            <ServiceCard
              key={service.id}
              nodeID={nodeID}
              service={service}
              reality={
                realities[
                  service.id
                ] ?? null
              }
            />
          )
        )}

        {services.length ===
          0 && (
          <div className="protocol-empty">
            Сервисы VLESS REALITY ещё не созданы.
          </div>
        )}
      </div>

      <details className="protocol-create">
        <summary>
          + Добавить протокол
        </summary>

        <div className="protocol-capability-grid">
          <a href="#reality-protocol-form" className="protocol-capability-item ready"><strong>VLESS</strong><span>TCP + REALITY</span><small>Создание в форме ниже</small></a>
          <a href="#tls-protocols" className="protocol-capability-item ready"><strong>VLESS</strong><span>TCP TLS / XHTTP TLS</span><small>Настройка в разделе «Протоколы с TLS»</small></a>
          <a href="#tls-protocols" className={agentSupportsWebTransports(agentVersion) ? "protocol-capability-item ready" : "protocol-capability-item"}><strong>VLESS</strong><span>WebSocket TLS / gRPC TLS</span><small>{agentSupportsWebTransports(agentVersion) ? "Доступно · раздел «Протоколы с TLS»" : "Требуется обновление агента до 0.2.26+"}</small></a>
          <a href="#tls-protocols" className="protocol-capability-item ready"><strong>Trojan</strong><span>TLS</span><small>Настройка в разделе «Протоколы с TLS»</small></a>
          <a href="#shadowsocks-protocols" className={agentSupportsWebTransports(agentVersion) ? "protocol-capability-item ready" : "protocol-capability-item"}><strong>Shadowsocks</strong><span>2022 · TCP / UDP</span><small>{agentSupportsWebTransports(agentVersion) ? "Доступно · раздел Shadowsocks ниже" : "Требуется обновление агента до 0.2.26+"}</small></a>
          <Link href="/nodes/new?runtime=hysteria2" className="protocol-capability-item ready"><strong>Hysteria2</strong><span>QUIC + TLS</span><small>Создать отдельную ноду Hysteria 2</small></Link>
          <a href="#wireguard-protocols" className={agentSupportsWebTransports(agentVersion) ? "protocol-capability-item ready" : "protocol-capability-item"}><strong>WireGuard</strong><span>Xray · TCP / UDP</span><small>{agentSupportsWebTransports(agentVersion) ? "Доступно · раздел WireGuard ниже" : "Требуется обновление агента до 0.2.26+"}</small></a>
          <Link href="/nodes/new?runtime=wireguard" className="protocol-capability-item ready"><strong>WireGuard Native</strong><span>TCP / UDP / ICMP</span><small>Новая отдельная нода · Agent 0.2.29</small></Link>
          <Link href="/nodes/new?runtime=amneziawg" className="protocol-capability-item ready"><strong>AmneziaWG</strong><span>1.0 · 1.5 · 2.0 · 3.0 · 3.1</span><small>Отдельная нода · выбор версии · Agent 0.2.42+</small></Link>
          <Link href="/nodes/new?runtime=openvpn" className="protocol-capability-item ready"><strong>OpenVPN</strong><span>UDP / TCP · TLS / PKI</span><small>Создать отдельную ноду OpenVPN</small></Link>
        </div>

        <form
          id="reality-protocol-form"
          action={createAction}
          className="protocol-form protocol-create-form"
        >
          <input
            type="hidden"
            name="node_id"
            value={nodeID}
          />

          <div className="protocol-form-grid">
            <label>
              <span>
                Название
              </span>

              <input
                name="name"
                required
                defaultValue="VLESS REALITY"
              />
            </label>

            <label>
              <span>
                Порт на ноде
              </span>

              <input
                type="number"
                name="port"
                min={1}
                max={65535}
                required
                defaultValue={443}
              />
            </label>

            <label>
              <span>
                Публичный адрес
              </span>

              <input
                name="public_address"
                required
                placeholder="vpn.example.com или IP"
              />
            </label>

            <label>
              <span>
                Публичный порт
              </span>

              <input
                type="number"
                name="public_port"
                min={1}
                max={65535}
                required
                defaultValue={443}
              />
            </label>

            <label>
              <span>
                REALITY Target
              </span>

              <input
                name="destination"
                required
                defaultValue="www.bing.com:443"
              />
            </label>

            <label>
              <span>
                SNI
              </span>

              <input
                name="server_name"
                required
                defaultValue="www.bing.com"
              />
            </label>

            <label>
              <span>
                Fingerprint
              </span>

              <select
                name="fingerprint"
                defaultValue="chrome"
              >
                <option value="chrome">
                  Chrome
                </option>
                <option value="firefox">
                  Firefox
                </option>
                <option value="edge">
                  Edge
                </option>
                <option value="safari">
                  Safari
                </option>
              </select>
            </label>
          </div>

          <div className="protocol-form-actions">
            <SubmitButton>
              Создать и применить
            </SubmitButton>
          </div>
        </form>

        <ActionMessage
          state={createState}
        />
      </details>
    </section>
  );
}

