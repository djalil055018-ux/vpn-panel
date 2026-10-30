import { SubscriptionNames } from "@/components/subscription-names";
import { ProtocolRuntimeSummary } from "@/components/protocol-runtime-summary";
import { PPTPServiceManager } from "@/components/pptp-service-manager";
import { InitializePPTP } from "@/components/pptp-setup";
import { OpenVPNServiceManager } from "@/components/openvpn-service-manager";
import { InitializeAmneziaWG, AmneziaWGServiceManager } from "@/components/amneziawg-manager";
import { getAmneziaWG } from "@/lib/control-plane";
import { InitializeWireGuard } from "@/components/wireguard-setup";
import { InitializeOpenVPN } from "@/components/openvpn-setup";
import Link from "next/link";
import { ShadowsocksServiceManager } from "@/components/shadowsocks-service-manager";
import { WireGuardServiceManager } from "@/components/wireguard-service-manager";
import { InitializeHysteria } from "@/components/hysteria-setup";
import { InitializeXray } from "@/components/xray-setup";
import { TLSServiceManager } from "@/components/tls-service-manager";
import { getTLSCertificates, getVPNServiceTLS } from "@/lib/control-plane";

import {
  ControlCenter,
} from "@/components/control-center";

import {
  StatusPill,
} from "@/components/status-pill";
import {
  ProtocolManager,
} from "@/components/protocol-manager";

import {
  getCoreReleases,
  getCoreUpdateStatus,
  getNode,
  getVPNServiceReality,
  getVPNServices,
} from "@/lib/control-plane";

import {
  ru,
} from "@/lib/i18n/ru";

export const dynamic =
  "force-dynamic";

export default async function NodeControlPage({
  params,
}: {
  params:
    Promise<{
      id: string;
    }>;
}) {
  const { id } =
    await params;

  const detail = await getNode(id);
  if (detail.node.status === "retired") return <section className="panel"><h1>Нода удалена</h1><p>Изменение конфигурации и обновление этой ноды недоступны.</p><Link href={`/nodes/${id}`} className="button">История ноды</Link></section>;
  const runtime = detail.node.runtime_core ?? "xray";

  const [
    releases,
    updateStatus,
    services,
  ] =
    await Promise.all([
      getCoreReleases(),
      getCoreUpdateStatus(
        id,
        runtime
      ),
      getVPNServices(id),
    ]);

  const awgEntries = await Promise.all(services.filter(s => s.protocol === "amneziawg").map(async s => { try { return [s.id, await getAmneziaWG(s.id)] as const; } catch { return [s.id, null] as const; } }));
  const awgConfigurations = Object.fromEntries(awgEntries);
  const realityEntries =
    await Promise.all(
      services.map(
        async (service) => {
          if (
            service.protocol !==
              "vless" ||
            service.transport !==
              "tcp" ||
            service.security !==
              "reality"
          ) {
            return [
              service.id,
              null,
            ] as const;
          }

          try {
            const reality =
              await getVPNServiceReality(
                service.id
              );

            return [
              service.id,
              reality,
            ] as const;
          } catch {
            return [
              service.id,
              null,
            ] as const;
          }
        }
      )
    );

  const realities =
    Object.fromEntries(
      realityEntries
    );

  const certificates = await getTLSCertificates(id);
  const tlsServices = services.filter(s => s.security === "tls" && (runtime === "hysteria2" ? s.protocol === "hysteria2" && s.transport === "udp" : ["vless", "trojan"].includes(s.protocol) && (s.transport === "tcp" || (["xhttp", "ws", "grpc"].includes(s.transport) && s.protocol === "vless"))));
  const tlsConfigurations = Object.fromEntries(await Promise.all(tlsServices.map(async s => {
    try { return [s.id, await getVPNServiceTLS(s.id)] as const; }
    catch { return [s.id, null] as const; }
  })));

  const compatible =
    releases.filter(
      (release) => {
        const core =
          release.type ??
          release.core_type ??
          "xray";

        if (core !== runtime) {
          return false;
        }
        if (runtime === "hysteria2" && (!release.id || release.id !== updateStatus.candidate_release_id)) {
          return false;
        }

        if (
          !release.approved ||
          release.revoked
        ) {
          return false;
        }

        if (
          release.architecture &&
          release.architecture !==
            detail.node.architecture
        ) {
          return false;
        }

        return true;
      }
    );

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            {ru.control.eyebrow}
          </div>

          <h1>
            {detail.node.name}
          </h1>

          <p>
            {ru.control.subtitle}
          </p>
        </div>

        <div className="header-actions">
          <StatusPill
            value={
              detail.lifecycle.state
            }
          />

          <Link
            className="button"
            href={`/nodes/${id}`}
          >
            {ru.control.backToNode}
          </Link>
        </div>
      </header>

      <section className="control-summary">
        <div>
          <span>
            Агент
          </span>

          <strong>
            {detail.node.agent_version ??
              "—"}
          </strong>
        </div>

        <div>
          <span>
            Текущее ядро
          </span>

          <strong>
            {detail.runtime
              .current_core_version ??
              "—"}
          </strong>
        </div>

        <div>
          <span>
            Поколение
          </span>

          <strong>
            {detail.node
              .desired_generation}
            {" / "}
            {detail.node
              .applied_generation}
          </strong>
        </div>

        <div>
          <span>
            Откат
          </span>

          <strong>
            {detail.runtime
              .rollback_ready
              ? "Готов"
              : "Недоступен"}
          </strong>
        </div>
      </section>

      <SubscriptionNames node={id} services={services} />

      <ProtocolRuntimeSummary
        node={detail.node}
        lifecycle={detail.lifecycle}
        runtime={runtime}
        services={services}
      />

      {runtime === "hysteria2" && detail.node.desired_generation === 0 && <InitializeHysteria node={id} registered={detail.lifecycle.registered} />}
      {runtime === "xray" && detail.node.desired_generation === 0 && <InitializeXray node={id} registered={detail.lifecycle.registered} />}
      {runtime === "xray" && detail.node.desired_generation > 0 && <ProtocolManager
        nodeID={id}
        agentVersion={detail.node.agent_version}
        services={services.filter(s => s.security !== "tls" && !["shadowsocks","wireguard"].includes(s.protocol))}
        realities={realities}
      />}

      {((runtime === "xray" && detail.node.desired_generation > 0) || runtime === "hysteria2") && <TLSServiceManager agentVersion={detail.node.agent_version} coreVersion={detail.runtime.current_core_version} node={id} runtime={runtime} services={tlsServices} certificates={certificates} configurations={tlsConfigurations} />}
      {runtime === "xray" && detail.node.desired_generation > 0 && <ShadowsocksServiceManager node={id} agentVersion={detail.node.agent_version} services={services.filter(s => s.protocol === "shadowsocks")} />}
      {runtime === "amneziawg" && detail.node.desired_generation === 0 && <InitializeAmneziaWG node={id} registered={detail.lifecycle.registered} />}
      {runtime === "amneziawg" && <AmneziaWGServiceManager node={id} agentVersion={detail.node.agent_version} initialized={detail.node.desired_generation > 0} services={services.filter(s => s.protocol === "amneziawg")} configurations={awgConfigurations} />}
      {runtime === "wireguard" && detail.node.desired_generation === 0 && <InitializeWireGuard node={id} registered={detail.lifecycle.registered} />}
      {((runtime === "xray" && detail.node.desired_generation > 0) || runtime === "wireguard") && <WireGuardServiceManager native={runtime === "wireguard"} initialized={detail.node.desired_generation > 0} node={id} agentVersion={detail.node.agent_version} services={services.filter(s => s.protocol === "wireguard")} />}

      {runtime === "pptp" && detail.node.desired_generation === 0 && <InitializePPTP node={id} registered={detail.lifecycle.registered} />}
      {runtime === "pptp" && <PPTPServiceManager node={id} initialized={detail.node.desired_generation > 0} services={services.filter(s=>s.protocol==="pptp")} />}
      {runtime === "openvpn" && detail.node.desired_generation === 0 && <InitializeOpenVPN node={id} registered={detail.lifecycle.registered} />}
      {runtime === "openvpn" && <OpenVPNServiceManager node={id} initialized={detail.node.desired_generation > 0} services={services.filter(s => s.protocol === "openvpn")} />}
      {((runtime === "xray" && detail.node.desired_generation > 0) || runtime === "hysteria2") && <ControlCenter
        nodeID={id}
        currentVersion={
          detail.runtime
            .current_core_version ??
          ""
        }
        latestGeneration={
          detail.lifecycle
            .latest_deployment_generation ??
          0
        }
        releases={compatible}
        coreUpdateStatus={
          updateStatus
        }
      />}
    </>
  );
}
