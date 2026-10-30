import type { Lifecycle, NodeRecord } from "./control-plane";

export function nodeMetricsEmptyMessage(
  node: Pick<NodeRecord, "agent_version">,
  lifecycle: Pick<Lifecycle, "registered" | "online" | "agent_version">,
): string {
  if (!lifecycle.registered) {
    return "Нода ещё не зарегистрирована. Метрики появятся после подключения агента.";
  }

  const version = node.agent_version?.trim() || lifecycle.agent_version?.trim();
  if (version && /^\d{1,6}\.\d{1,6}\.\d{1,6}$/.test(version)) {
    const [major, minor, patch] = version.split(".").map(Number);
    if (major === 0 && (minor < 2 || (minor === 2 && patch < 18))) {
      return `Нет метрик за выбранный период. Для передачи метрик нужен Agent 0.2.18 или новее; установлен ${version}.`;
    }
  }

  if (!lifecycle.online) {
    return "Нет метрик за выбранный период. Нода не в сети. Выберите другой период или проверьте связь с агентом.";
  }

  return "Нет метрик за выбранный период. Выберите другой период или дождитесь следующего отчёта агента.";
}
