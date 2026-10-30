import type {
  VPNClientConnection,
} from "./control-plane";

export type ConnectionDescriptor =
  Pick<
    VPNClientConnection,
    | "protocol"
    | "transport"
    | "security"
    | "runtime_core"
    | "amneziawg_version"
  >;

export function connectionLabel(
  connection: ConnectionDescriptor
) {
  if (connection.protocol === "amneziawg") return `AmneziaWG ${connection.amneziawg_version ?? ""} · TCP / UDP / ICMP`;
  if (connection.protocol === "pptp") return "PPTP · legacy · MPPE128";
  if (
    connection.protocol === "wireguard"
  ) {
    if (
      connection.runtime_core ===
      "wireguard"
    ) {
      return "WireGuard Native · TCP / UDP / ICMP";
    }

    if (
      connection.runtime_core ===
      "xray"
    ) {
      return "WireGuard через Xray · TCP / UDP";
    }

    return "WireGuard";
  }

  if (
    connection.protocol === "openvpn"
  ) {
    return `OpenVPN · ${connection.transport.toUpperCase()} · TLS / PKI`;
  }

  if (
    connection.protocol ===
    "shadowsocks"
  ) {
    return "Shadowsocks 2022 · TCP / UDP";
  }

  if (
    connection.protocol ===
    "hysteria2"
  ) {
    return "Hysteria 2 · QUIC / UDP · TLS";
  }

  if (
    connection.protocol === "trojan"
  ) {
    return "Trojan · TCP · TLS";
  }

  if (
    connection.security === "tls"
  ) {
    return `VLESS ${connection.transport.toUpperCase()} · TLS`;
  }

  return "VLESS · TCP · REALITY";
}

export function connectionImportHint(
  connection: ConnectionDescriptor
) {
  if (connection.protocol === "amneziawg") return "Импортируйте .conf или QR в приложение AmneziaWG с поддержкой указанной версии. Обычный клиент WireGuard не поддерживает параметры AmneziaWG. Для роутера проверьте поддержку этой версии прошивкой.";
  if (connection.protocol === "pptp") return "Скачайте инструкцию с адресом, логином и паролем для ручной настройки PPTP. Нужны TCP 1723 и GRE (IP 47), MS-CHAPv2 и MPPE. PPTP имеет известные ограничения безопасности и предназначен для совместимости со старыми устройствами.";
  if (
    connection.protocol === "wireguard"
  ) {
    return "Импортируйте файл .conf в WireGuard или отсканируйте QR-код в приложении WireGuard. Обычная ссылка подписки не заменяет этот профиль.";
  }

  if (
    connection.protocol === "openvpn"
  ) {
    return "Импортируйте файл .ovpn в OpenVPN Connect или совместимое приложение. Обычная ссылка подписки не заменяет этот профиль.";
  }

  return "Импортируйте ссылку или QR-код в VPN-приложение с поддержкой указанного протокола и транспорта.";
}
