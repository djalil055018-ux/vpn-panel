import type { VPNClientConnection } from "./control-plane";
import { connectionLabel } from "./connection-labels";

type Entry = { name: string; text: string };
const encoder = new TextEncoder();

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Stored ZIP entries need no compression dependency or server-side secret files.
export function connectionArchive(connections: VPNClientConnection[]): Uint8Array<ArrayBuffer> {
  const entries: Entry[] = [];
  const links: string[] = [];
  const descriptions: string[] = [];
  const seen = new Set<string>();
  for (const connection of connections) {
    const id = connection.service_id.toLowerCase();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) || seen.has(id)) throw new Error("Invalid profile identity");
    seen.add(id);
    if (connection.protocol === "pptp" || connection.protocol === "amneziawg" || connection.protocol === "wireguard" || connection.protocol === "openvpn") {
      if (!connection.config) throw new Error("Missing profile");
      const name = `${connection.protocol}-${id}.${connection.protocol === "pptp" ? "pptp.txt" : connection.protocol === "openvpn" ? "ovpn" : "conf"}`;
      entries.push({ name, text: connection.config });
      descriptions.push(`${name} — ${connection.service_name.replace(/[\r\n\u0000-\u001f]/g, " ")} · ${connectionLabel(connection)}`);
    } else {
      if (!connection.uri || !/^(vless|trojan|ss|hysteria2|hy2):\/\/[^\r\n]+$/.test(connection.uri)) throw new Error("Missing connection link");
      links.push(connection.uri);
    }
  }
  if (!seen.size) throw new Error("No active profiles");
  if (links.length) entries.push({ name: "connections.txt", text: links.join("\n") + "\n" });
  entries.push({ name: "README.txt", text: [
    "Профили VPN", "",
    "connections.txt: импортируйте ссылки в приложение, поддерживающее соответствующий протокол.",
    ".conf: импортируйте файл в WireGuard. Native поддерживает TCP, UDP и ICMP; вариант через Xray — TCP и UDP. Тип каждого профиля указан ниже, если его сообщает сервер.",
    "amneziawg-*.conf: импортируйте в AmneziaWG, поддерживающий указанную версию. Обычный клиент WireGuard не подходит.",
    ".pptp.txt: данные и инструкция для ручной настройки PPTP. Это устаревший протокол совместимости; нужны TCP 1723 и GRE (IP 47).",
    ".ovpn: импортируйте файл в OpenVPN. Перед окончанием срока сертификата скачайте новый профиль.",
    "",
    "Архив содержит ключи доступа. Передавайте его только владельцу этих подключений.",
    "Архив не обновляется автоматически. Отзыв доступа отключает ранее выданные профили.",
    "", ...descriptions, "",
  ].join("\r\n") });
  if (entries.length > 65535) throw new Error("Too many profiles");
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = encoder.encode(entry.name), data = encoder.encode(entry.text);
    if (offset + data.length > 16 * 1024 * 1024) throw new Error("Profile archive too large");
    const checksum = crc32(data);
    const local = new Uint8Array(30 + name.length), lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(6, 0x0800, true);
    lv.setUint16(12, 33, true); lv.setUint32(14, checksum, true);
    lv.setUint32(18, data.length, true); lv.setUint32(22, data.length, true); lv.setUint16(26, name.length, true); local.set(name, 30);
    const directory = new Uint8Array(46 + name.length), dv = new DataView(directory.buffer);
    dv.setUint32(0, 0x02014b50, true); dv.setUint16(4, 20, true); dv.setUint16(6, 20, true); dv.setUint16(8, 0x0800, true);
    dv.setUint16(14, 33, true); dv.setUint32(16, checksum, true); dv.setUint32(20, data.length, true); dv.setUint32(24, data.length, true);
    dv.setUint16(28, name.length, true); dv.setUint32(42, offset, true); directory.set(name, 46);
    parts.push(local, data); central.push(directory); offset += local.length + data.length;
  }
  const centralSize = central.reduce((sum, entry) => sum + entry.length, 0);
  const end = new Uint8Array(22), ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, entries.length, true); ev.setUint16(10, entries.length, true);
  ev.setUint32(12, centralSize, true); ev.setUint32(16, offset, true);
  const result = new Uint8Array(offset + centralSize + end.length);
  let position = 0;
  for (const part of [...parts, ...central, end]) { result.set(part, position); position += part.length; }
  return result;
}
