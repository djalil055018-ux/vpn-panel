export type Cascade = {
  id: string; tenant_id: string; name: string; plan_id: string;
  entry_service_id: string; exit_service_id: string; entry_node_id: string; exit_node_id: string;
  entry_port: number; enabled: boolean; created_at: string; updated_at: string;
  state: string; entry_node_name: string; exit_node_name: string; plan_name: string;
  entry_agent_version: string; exit_agent_version: string;
  entry_desired_generation: number; entry_applied_generation: number;
  exit_desired_generation: number; exit_applied_generation: number;
};
export type CascadeInput = Pick<Cascade, "name" | "plan_id" | "entry_service_id" | "exit_service_id" | "entry_port" | "enabled">;
export type CascadeMutation = { changed: boolean; rebuilds: { node_id: string; generation: number }[] };
export type CascadeService = { id: string; name: string; node_id: string; node_name: string; agent_version: string; enabled: boolean; port: number };
export type CascadePlan = { id: string; name: string; enabled: boolean };
export function cascadeAgentReady(version: string) {
  const match = version.match(/^0\.2\.(\d+)$/);
  return Boolean(match && Number(match[1]) >= 34);
}
export const cascadeStates: Record<string, { label: string; tone: string; description: string }> = {
  active: { label: "Применён", tone: "good", description: "Оба сервера применили конфигурацию. Профиль доступен активным клиентам группы." },
  disabled: { label: "Отключён", tone: "neutral", description: "Профиль скрыт из подписок. Сохранённые настройки можно включить позже." },
  inactive: { label: "Доступ приостановлен", tone: "warn", description: "Проверьте, включены ли группа и оба VPN-сервиса." },
  agent_update_required: { label: "Нужно обновление", tone: "warn", description: "На обоих серверах нужен агент 0.2.34 или новее." },
  offline: { label: "Сервер недоступен", tone: "warn", description: "Один из серверов не выходит на связь. Проверьте раздел «Серверы»." },
  failed: { label: "Ошибка применения", tone: "bad", description: "Конфигурация не прошла проверку на сервере. Подробности — в разделе «Развёртывания»." },
  pending: { label: "Применяется", tone: "warn", description: "Профиль появится после подтверждения новой конфигурации обоими серверами." },
};
