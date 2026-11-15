import { nodeRestoreEvidenceState, type NodeRestoreEvidence } from "@/lib/operations-health";
import type { BackupStatus } from "@/lib/control-plane";

function when(value: string | null) {
  return value && Number.isFinite(Date.parse(value)) ? new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Moscow" }).format(new Date(value)) : "Ещё нет";
}

export function NodeRestoreCheck({ restore, backup, at, nodeID }: { restore: NodeRestoreEvidence | null; backup: BackupStatus | null; at: string; nodeID: string }) {
  const state = nodeRestoreEvidenceState(restore, backup, at, nodeID);
  const verified = restore && (state === "verified_current_backup" || state === "verified_historical");
  return <div className="operations-backup operations-node-restore">
    <strong className={state === "verified_current_backup" ? "operations-good" : "operations-warning"}>{state === "verified_current_backup" ? "Конфигурация этой копии запускалась" : state === "verified_historical" ? "Есть результат более ранней проверки" : state === "failed" ? "Пробный запуск этой копии не завершился" : state === "failed_historical" ? "Более ранняя проверка не завершилась" : state === "missing" ? "Пробный запуск копии ноды ещё не проверен" : "Нет достоверного результата пробного запуска"}</strong>
    {verified && <>
      <span>{when(restore.verified_at)} · Xray {restore.core_version} · Проверено слушателей TCP: {restore.expected_tcp_listeners}</span>
      <span>Проверенная копия: {restore.backup_id}</span>
      {state === "verified_historical" && <span>Этот результат не подтверждает запуск последней свежей копии.</span>}
      <span>Конфигурация запускалась без внешней сети с уже установленным ядром. Полное восстановление ноды на новом сервере ещё не проверено.</span>
    </>}
    {restore && (state === "failed" || state === "failed_historical") && <span>{when(restore.checked_at)} · Копия: {restore.backup_id}</span>}
  </div>;
}
