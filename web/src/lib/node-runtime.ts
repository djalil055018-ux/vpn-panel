import { installationOrigin } from "./installation-origin";

export type NodeRuntime = "xray" | "hysteria2" | "openvpn" | "wireguard" | "pptp" | "amneziawg";

export function agentSupportsNodeReboot(version?: string | null) {
  const match = version?.trim().match(/^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
  if (!match) return false;
  const actual = match.slice(1).map(Number);
  const minimum = [0, 2, 39];
  for (let i = 0; i < minimum.length; i += 1) {
    if (actual[i] !== minimum[i]) return actual[i] > minimum[i];
  }
  return true;
}

export function runtimeLabel(runtime: NodeRuntime) {
  return runtime === "amneziawg" ? "AmneziaWG" : runtime === "pptp" ? "PPTP · legacy" : runtime === "wireguard" ? "WireGuard Native" : runtime === "openvpn" ? "OpenVPN" : runtime === "hysteria2" ? "Hysteria 2" : "Xray";
}

function validatedOrigin(value: string) {
  const origin = installationOrigin(value);
  if (!origin) throw new Error("Адрес панели для установки не настроен.");
  return origin;
}

export function agentUpdaterInstallCommand(publicOrigin: string) {
  const origin = validatedOrigin(publicOrigin);
  return `curl -fsSL ${origin}/install/vpn-agent-updater-v0.1.0.py -o /root/vpn-agent-updater.py && curl -fsSL ${origin}/install/install-vpn-agent-updater-v0.1.0.py -o /root/install-vpn-agent-updater.py && echo '485a34aca4630548f2930f24a0f7ae73cf910611749bcd649a0126597cdb7fde  /root/vpn-agent-updater.py' | sha256sum -c - && echo '6298b66dc56255cfad6530307db50a9d320c74e0da511b39c119fffa6505d370  /root/install-vpn-agent-updater.py' | sha256sum -c - && chmod 600 /root/vpn-agent-updater.py /root/install-vpn-agent-updater.py && python3 /root/install-vpn-agent-updater.py --artifact-file /root/vpn-agent-updater.py --start`;
}

export function nodeInstallCommand(runtime: NodeRuntime, nodeID: string, publicOrigin: string) {
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(nodeID) || !["xray", "hysteria2", "wireguard", "openvpn", "pptp", "amneziawg"].includes(runtime)) {
    throw new Error("Не удалось определить сервер для установки.");
  }
  const origin = validatedOrigin(publicOrigin);
  if (runtime === "hysteria2") {
    return `curl -fsSL ${origin}/install/vpn-node-tool-v0.2.43.py -o /root/vpn-node-tool.py && echo '3184251689e75751c1a9edd8bdd5bab189cea87cbf6a163ca6e4b736fa761873  /root/vpn-node-tool.py' | sha256sum -c - && curl -fsSL ${origin}/artifacts/node-agent/0.2.43/linux-amd64/vpn-node-agent -o /root/vpn-node-agent.download && echo '44434e3f54508e4e56eb3b5cdaa0fb1d59f6a189f9cbe5f64350cac78a022adf  /root/vpn-node-agent.download' | sha256sum -c - && chmod 700 /root/vpn-node-tool.py && chmod 600 /root/vpn-node-agent.download && python3 /root/vpn-node-tool.py install --control-plane ${origin} --artifact-file /root/vpn-node-agent.download --require-bootstrap --expected-node-id ${nodeID} --core hysteria2 && ${agentUpdaterInstallCommand(origin)}`;
  }
  if (runtime === "amneziawg") {
    return `curl -fsSL ${origin}/install/vpn-node-tool-v0.2.42.py -o /root/vpn-node-tool.py && echo 'f6e6e1275eab3af6af33edee4ac33970b244443189a386339807b714a8d02b9d  /root/vpn-node-tool.py' | sha256sum -c - && curl -fsSL ${origin}/artifacts/node-agent/0.2.42/linux-amd64/vpn-node-agent -o /root/vpn-node-agent.download && echo '81cd3db30b198795a634e626471053774ad567b852a19b52a4d32f6675fa67f3  /root/vpn-node-agent.download' | sha256sum -c - && curl -fsSL ${origin}/artifacts/cores/amneziawg/3.1.20260828-pauk.1/linux-amd64.tar.gz -o /root/pauk-amneziawg.tar.gz && echo '1fc10912a24cc14178f3937552bd8c6a9d6489d8462f0884053a9ea3091e886a  /root/pauk-amneziawg.tar.gz' | sha256sum -c - && chmod 700 /root/vpn-node-tool.py && chmod 600 /root/vpn-node-agent.download /root/pauk-amneziawg.tar.gz && python3 /root/vpn-node-tool.py install --control-plane ${origin} --artifact-file /root/vpn-node-agent.download --runtime-artifact-file /root/pauk-amneziawg.tar.gz --require-bootstrap --expected-node-id ${nodeID} --core amneziawg && ${agentUpdaterInstallCommand(origin)}`;
  }
  const pptpDownload = runtime === "pptp" ? `curl -fsSL ${origin}/artifacts/pptp/1.14.0-platform.1/linux-amd64/pptp-accel-1.14.0-platform.1-linux-amd64.tar.gz -o /root/pauk-pptp.tar.gz && echo 'd6960405b74030750e7b835e3dafef76e26f1d2748a4d347578204fabcdd08a6  /root/pauk-pptp.tar.gz' | sha256sum -c - && ` : "";
  const pptpOption = runtime === "pptp" ? " --runtime-artifact-file /root/pauk-pptp.tar.gz" : "";
  return `curl -fsSL ${origin}/install/vpn-node-tool-v0.2.39.py -o /root/vpn-node-tool.py && echo 'aec3ab490453f0a0808c40e1be848e64b7b63538495ec8c8af3c5823b16b6288  /root/vpn-node-tool.py' | sha256sum -c - && curl -fsSL ${origin}/artifacts/node-agent/0.2.39/linux-amd64/vpn-node-agent -o /root/vpn-node-agent.download && echo '41c744f44b62ee9b58d1961f0609ddf60de419db3ba71271fd13aa16f615db8b  /root/vpn-node-agent.download' | sha256sum -c - && chmod 700 /root/vpn-node-tool.py && ${pptpDownload}python3 /root/vpn-node-tool.py install --control-plane ${origin} --artifact-file /root/vpn-node-agent.download --require-bootstrap --expected-node-id ${nodeID} --core ${runtime}${pptpOption} && ${agentUpdaterInstallCommand(origin)}`;
}

export function tlsProtocol(runtime: NodeRuntime, choice: string) {
  if (runtime === "pptp" || runtime === "openvpn" || runtime === "wireguard" || runtime === "amneziawg") return null;
  if (runtime === "hysteria2") return choice === "hysteria2" ? { protocol: "hysteria2", transport: "udp" } : null;
  if (choice === "vless-ws") return { protocol: "vless", transport: "ws" };
  if (choice === "vless-grpc") return { protocol: "vless", transport: "grpc" };
  if (choice === "vless-xhttp") return { protocol: "vless", transport: "xhttp" };
  if (choice === "vless" || choice === "trojan") return { protocol: choice, transport: "tcp" };
  return null;
}

export function supportsClientProvisioning(service: { protocol: string; transport: string; security: string }) {
  const { protocol, transport, security } = service;
  if (protocol === "pptp") return transport === "tcp,gre" && security === "mppe";
  if (protocol === "openvpn") return ["udp","tcp"].includes(transport) && security === "tls";
  if (protocol === "amneziawg") return transport === "udp" && security === "amneziawg";
  if (protocol === "wireguard") return transport === "udp" && security === "wireguard";
  if (protocol === "shadowsocks") return transport === "tcp,udp" && security === "shadowsocks";
  if (protocol === "hysteria2") return transport === "udp" && security === "tls";
  if (protocol === "vless" && transport === "tcp" && security === "reality") return true;
  return security === "tls" && ((["vless", "trojan"].includes(protocol) && transport === "tcp") || (protocol === "vless" && ["xhttp", "ws", "grpc"].includes(transport)));
}
function agentAtLeast(version: string | null | undefined, minimum: [number, number, number]) {
  const match = version?.trim().match(/^(\d{1,6})\.(\d{1,6})\.(\d{1,6})$/);
  if (!match) return false;
  const actual = match.slice(1).map(Number);
  for (let i = 0; i < minimum.length; i += 1) {
    if (actual[i] !== minimum[i]) return actual[i] > minimum[i];
  }
  return true;
}

export function agentSupportsVLESSTLS(version?: string | null) {
  return agentAtLeast(version, [0, 2, 15]);
}

export function agentSupportsVLESSXHTTP(version?: string | null) {
  return agentAtLeast(version, [0, 2, 17]);
}

export function agentSupportsWebTransports(version?: string | null) {
  return agentAtLeast(version, [0, 2, 26]);
}

export function xraySupportsXHTTP(version?: string | null) {
  const match = version?.trim().match(/^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})$/);
  if (!match) return false;
  const actual = match.slice(1).map(Number);
  const minimum = [26, 7, 28];
  for (let i = 0; i < minimum.length; i += 1) {
    if (actual[i] !== minimum[i]) return actual[i] > minimum[i];
  }
  return true;
}

export function agentSupportsNativeWireGuard(version?: string) {
  if (!version || !/^\d{1,6}\.\d{1,6}\.\d{1,6}$/.test(version)) return false;
  const [major,minor,patch] = version.split(".").map(Number);
  return major > 0 || minor > 2 || (minor === 2 && patch >= 28);
}

export function agentSupportsAmneziaWG(version?: string | null) { return agentAtLeast(version, [0, 2, 42]); }
