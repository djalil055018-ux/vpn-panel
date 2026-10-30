import type {
  Lifecycle,
  VPNServiceRecord,
} from "./control-plane";

import type {
  NodeRuntime,
} from "./node-runtime";

export type ProtocolTone =
  | "success"
  | "warning"
  | "danger"
  | "neutral";

export type Presentation = {
  label: string;
  tone: ProtocolTone;
};

export type ServicePresentation = {
  label: string;
  profile: string;
  traffic: string;
  agentRequirement: string;
  endpoint: string;
  state: Presentation;
};

export function generationPresentation(
  desired: number,
  applied: number,
  registered: boolean
): Presentation {
  if (applied > desired) {
    return {
      label: `Несоответствие · ${desired} / ${applied}`,
      tone: "danger",
    };
  }

  if (!registered) {
    return {
      label: `Ожидает регистрации · ${desired} / ${applied}`,
      tone: "warning",
    };
  }

  if (desired === 0 && applied === 0) {
    return {
      label: "Начальное состояние · 0 / 0",
      tone: "neutral",
    };
  }

  if (desired === applied) {
    return {
      label: `Применено · ${desired} / ${applied}`,
      tone: "success",
    };
  }

  return {
    label: `Ожидает применения · ${desired} / ${applied}`,
    tone: "warning",
  };
}

export function nodeHealthPresentation(
  lifecycle: Lifecycle
): Presentation {
  if (!lifecycle.registered) {
    return {
      label: "Не зарегистрирована",
      tone: "warning",
    };
  }

  if (!lifecycle.online) {
    return {
      label: "Offline",
      tone: "danger",
    };
  }

  if (!lifecycle.health_present) {
    return {
      label: "Health ещё не получен",
      tone: "warning",
    };
  }

  if (!lifecycle.health_fresh) {
    return {
      label: "Health устарел",
      tone: "warning",
    };
  }

  if (!lifecycle.healthy) {
    return {
      label: "Degraded",
      tone: "danger",
    };
  }

  return {
    label: "Healthy",
    tone: "success",
  };
}

function endpoint(
  service: VPNServiceRecord
) {
  const address =
    service.public_address?.trim() ||
    service.listen;

  const port =
    service.public_port ??
    service.port;

  const host =
    address.includes(":")
      ? `[${address}]`
      : address;

  return `${host}:${port}`;
}

function transportLabel(
  transport: string
) {
  if (transport === "xhttp") {
    return "XHTTP";
  }

  if (transport === "ws") {
    return "WebSocket";
  }

  if (transport === "grpc") {
    return "gRPC";
  }

  return transport.toUpperCase();
}

export function servicePresentation(
  service: VPNServiceRecord,
  runtime: NodeRuntime
): ServicePresentation {
  const state: Presentation =
    service.enabled
      ? {
          label: "Включён",
          tone: "success",
        }
      : {
          label: "Отключён",
          tone: "neutral",
        };

  if (service.protocol === "amneziawg") return {label:"AmneziaWG",profile:".conf + QR · клиент AmneziaWG",traffic:"TCP / UDP / ICMP",agentRequirement:"Agent 0.2.42+",endpoint:endpoint(service),state};
  if (service.protocol === "wireguard") {
    if (runtime === "wireguard") {
      return {
        label: "WireGuard Native",
        profile: ".conf + QR",
        traffic: "TCP / UDP / ICMP",
        agentRequirement:
          "Минимум 0.2.28 · для новых нод 0.2.29",
        endpoint: endpoint(service),
        state,
      };
    }

    return {
      label: "WireGuard через Xray",
      profile: ".conf + QR",
      traffic: "TCP / UDP",
      agentRequirement:
        "Agent 0.2.26+",
      endpoint: endpoint(service),
      state,
    };
  }

  if (service.protocol === "pptp") {
    return {label:"PPTP · legacy · MPPE128",profile:"Инструкция .pptp.txt · без QR",traffic:"IPv4 · TCP 1723 + GRE",agentRequirement:"Отдельная нода: Agent 0.2.30+",endpoint:endpoint(service),state};
  }
  if (service.protocol === "openvpn") {
    return {
      label:
        `OpenVPN · ${service.transport.toUpperCase()} · TLS / PKI`,
      profile: ".ovpn · без QR",
      traffic:
        service.transport.toUpperCase(),
      agentRequirement:
        "Новые ноды: Agent 0.2.27",
      endpoint: endpoint(service),
      state,
    };
  }

  if (service.protocol === "shadowsocks") {
    return {
      label:
        "Shadowsocks 2022 · TCP / UDP",
      profile: "URI + QR",
      traffic: "TCP / UDP",
      agentRequirement:
        "Agent 0.2.26+",
      endpoint: endpoint(service),
      state,
    };
  }

  if (service.protocol === "hysteria2") {
    return {
      label:
        "Hysteria 2 · QUIC / UDP · TLS",
      profile: "URI + QR",
      traffic: "QUIC / UDP",
      agentRequirement:
        "Agent 0.2.25+",
      endpoint: endpoint(service),
      state,
    };
  }

  if (service.protocol === "trojan") {
    return {
      label:
        "Trojan · TCP · TLS",
      profile: "URI + QR",
      traffic: "TCP",
      agentRequirement:
        "Agent 0.2.16+",
      endpoint: endpoint(service),
      state,
    };
  }

  if (
    service.protocol === "vless" &&
    service.security === "reality"
  ) {
    return {
      label:
        "VLESS · TCP · REALITY",
      profile: "URI + QR",
      traffic: "TCP",
      agentRequirement:
        "Xray Agent",
      endpoint: endpoint(service),
      state,
    };
  }

  if (
    service.protocol === "vless" &&
    service.security === "tls"
  ) {
    const requirement =
      service.transport === "ws" ||
      service.transport === "grpc"
        ? "Agent 0.2.26+"
        : service.transport === "xhttp"
          ? "Agent 0.2.17+"
          : "Agent 0.2.15+";

    return {
      label:
        `VLESS · ${transportLabel(service.transport)} · TLS`,
      profile: "URI + QR",
      traffic:
        transportLabel(
          service.transport
        ),
      agentRequirement:
        requirement,
      endpoint: endpoint(service),
      state,
    };
  }

  return {
    label:
      `${service.protocol.toUpperCase()} · ${service.transport.toUpperCase()} · ${service.security.toUpperCase()}`,
    profile:
      "По конфигурации сервиса",
    traffic:
      service.transport.toUpperCase(),
    agentRequirement:
      "Проверить совместимость Agent",
    endpoint: endpoint(service),
    state,
  };
}
