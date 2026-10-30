export type UpdateActionState = { ok: boolean; message: string };
export type AgentFleetNode = { id: string; name: string; agent_version: string | null; registered: boolean; online: boolean; updater_online: boolean; updater_version: string | null; platform_supported: boolean; agent_update_eligible: boolean };
export type AgentFleetJob = { id: string; node_id: string; from_version: string; status: string; message: string; claimed_at: string | null; completed_at: string | null };
export type AgentFleetRun = { id: string; target_version: string; status: string; message: string; created_at: string; jobs: AgentFleetJob[] };
export type AgentFleetStatus = { policy: { auto_spread: boolean; target_version: string | null }; releases: { version: string; revoked: boolean }[]; runs: AgentFleetRun[]; nodes: AgentFleetNode[] };
export type XrayReleaseChoice = { id: string; version: string; approved: boolean; prerelease: boolean };

export function newerVersion(candidate: string, current: string) {
  if (!/^\d+\.\d+\.\d+$/.test(candidate) || !/^\d+\.\d+\.\d+$/.test(current)) return false;
  const a = candidate.split(".").map(Number), b = current.split(".").map(Number);
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] > b[i]; }
  return false;
}
export const updateStatusLabels: Record<string, string> = {
  queued: "В очереди", claimed: "Обновляется", succeeded: "Обновлено", failed: "Ошибка", already_current: "Уже установлено", superseded: "Установлена более новая версия",
  running: "Выполняется", paused: "Приостановлено", completed: "Завершено", pending: "Ожидает агента", applying: "Устанавливается", healthy: "Работает", rolled_back: "Выполнен откат",
};
