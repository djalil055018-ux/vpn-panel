export const AMNEZIAWG_VERSIONS = ["1.0", "1.5", "2.0", "3.0", "3.1"] as const;
export type AmneziaWGVersion = typeof AMNEZIAWG_VERSIONS[number];
export function isAmneziaWGVersion(value: string): value is AmneziaWGVersion {
  return (AMNEZIAWG_VERSIONS as readonly string[]).includes(value);
}
export const AMNEZIAWG_COMPATIBILITY = "Нужно приложение или прошивка с поддержкой выбранной версии AmneziaWG. Обычный клиент WireGuard не поддерживает эти параметры. После смены версии заново импортируйте конфигурацию на устройствах.";
