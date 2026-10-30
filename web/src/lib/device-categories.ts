export type DeviceCategory = "smartphone" | "router";

const protocolCategories: Record<string, readonly DeviceCategory[]> = {
  vless: ["smartphone"],
  vmess: ["smartphone"],
  trojan: ["smartphone"],
  shadowsocks: ["smartphone"],
  hysteria2: ["smartphone"],
  openvpn: ["smartphone", "router"],
  wireguard: ["smartphone", "router"],
  amneziawg: ["smartphone", "router"],
  pptp: ["router"],
  l2tp: ["router"],
  sstp: ["router"],
  ikev2: ["router"],
};

export function categoriesForProtocols(protocols: Iterable<string>): DeviceCategory[] {
  const found = new Set<DeviceCategory>();
  for (const protocol of protocols) {
    for (const category of protocolCategories[protocol.trim().toLocaleLowerCase("en-US")] ?? []) {
      found.add(category);
    }
  }
  const ordered: DeviceCategory[] = ["smartphone", "router"];
  return ordered.filter((category) => found.has(category));
}

export function categoriesForNode(protocols: Iterable<string>, runtimeCore?: string | null): DeviceCategory[] {
  const configured = categoriesForProtocols(protocols);
  if (configured.length) return configured;

  const runtime = runtimeCore?.trim().toLocaleLowerCase("en-US");
  if (runtime === "pptp" || runtime === "l2tp" || runtime === "sstp" || runtime === "ikev2") return ["router"];
  if (runtime === "openvpn" || runtime === "wireguard" || runtime === "wireguard-native" || runtime === "amneziawg") return ["smartphone", "router"];
  return ["smartphone"];
}
