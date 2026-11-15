import Link from "next/link";
import { getControlPlaneHealth, getOperationsStatus, type BackupStatus, type OperationsStatus } from "@/lib/control-plane";
import { backupFreshAt, restoreEvidenceState } from "@/lib/operations-health";
import { NodeRestoreCheck } from "@/components/node-restore-check";

export const dynamic = "force-dynamic";
function when(value: string | null) { return value && Number.isFinite(Date.parse(value)) ? new Intl.DateTimeFormat("ru-RU", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Moscow" }).format(new Date(value)) : "Ещё нет"; }
function bytes(value: number) { return value < 0 ? "Нет данных" : `${(value / 1024 ** 3).toFixed(1)} ГБ`; }
function Backup({ backup, at }: { backup: BackupStatus | null; at: string }) {
  const good = backupFreshAt(backup, at);
  const description = backup?.status === "verified" ? backup.verification === "database_restore" ? "Восстановление в отдельную БД проверено" : backup.verification === "archive_integrity" ? "Целостность архива проверена на ноде" : "Метод проверки не подтверждён" : "Последняя сохранённая копия";
  return <div className="operations-backup"><strong className={good ? "operations-good" : "operations-warning"}>{good ? "Свежая проверенная копия" : backup?.status === "failed" ? "Ошибка резервного копирования" : "Нужна свежая проверенная копия"}</strong><span>{when(backup?.last_success_at ?? null)}</span>{backup && <span>{description} · {(backup.size_bytes / 1024 ** 2).toFixed(0)} МБ</span>}</div>;
}
function RestoreCheck({ data, runningVersion }: { data: OperationsStatus; runningVersion: string | null }) {
  const restore = data.restore_drill;
  const state = restoreEvidenceState(restore, data.control_plane_backup, data.generated_at, runningVersion);
  if (restore && (state === "verified_current_backup" || state === "verified_historical" || state === "verified_current_backup_other_release" || state === "verified_current_backup_release_unknown")) return <>
    <strong className={state === "verified_current_backup" ? "operations-good" : "operations-warning"}>{state === "verified_current_backup" ? "Последняя копия успешно запускалась" : state === "verified_current_backup_other_release" ? "Последняя копия запускалась; версия отличается" : state === "verified_current_backup_release_unknown" ? "Последняя копия запускалась; текущая версия неизвестна" : "Проверен запуск более ранней копии"}</strong>
    <p>{when(restore.verified_at)} · Control Plane {restore.control_plane_version}</p>
    <p>Проверено страниц: {restore.web_pages} · Время проверки: {Math.ceil(restore.duration_seconds / 60)} мин.</p>
    <p className="plan-muted">Копия: {restore.backup_id}</p>
    {state === "verified_historical" && <p>Этот результат не подтверждает запуск последней свежей копии. Нужна новая проверка восстановления.</p>}
    {state === "verified_current_backup_other_release" && <p>В копии сохранён Control Plane {restore.control_plane_version}. Сейчас работает Control Plane {runningVersion}. Результат подтверждает запуск указанной копии с её сохранённой версией.</p>}
    {state === "verified_current_backup_release_unknown" && <p>Не удалось определить текущую версию Control Plane. Результат подтверждает запуск указанной копии с её сохранённой версией.</p>}
  </>;
  if (state === "failed") return <><strong className="operations-warning">Последняя проверка восстановления не завершилась</strong><p>{when(restore?.checked_at ?? null)}</p></>;
  return <p className="plan-muted">{state === "missing" ? "Проверка запуска восстановленной копии ещё не выполнялась." : "Нет достоверного результата проверки восстановления."}</p>;
}
export default async function OperationsPage() {
  const [operations, health] = await Promise.allSettled([getOperationsStatus(), getControlPlaneHealth()]);
  const data = operations.status === "fulfilled" ? operations.value : null;
  const runningVersion = health.status === "fulfilled" && health.value.status === "ok" ? health.value.version : null;
  if (!data) return <section className="panel"><div className="panel-header"><div><h1>Состояние платформы</h1><p>Не удалось получить состояние. Обновите страницу немного позже.</p></div></div></section>;
  const healthy = data.nodes.filter(n => n.lifecycle.online && n.lifecycle.healthy && n.lifecycle.health_fresh && n.lifecycle.desired_generation === n.lifecycle.applied_generation).length;
  const backups = data.nodes.filter(n => backupFreshAt(n.backup, data.generated_at)).length;
  return <>
    <header className="page-header"><div><h1>Состояние платформы</h1><p>Работа нод, сертификаты и проверенные резервные копии.</p></div><div className="plan-actions"><Link href="/incidents" className="button ghost">Журнал инцидентов</Link><Link href="/operations" className="button ghost">Обновить</Link></div></header>
    {data.pending_access_nodes > 0 && <div className="alert error">На нодах ожидает снятия неактивный клиентский доступ: {data.pending_access_nodes}. Проверка выполняется каждую минуту; если предупреждение сохраняется, проверьте ноды и службу контроля доступа.</div>}
    <div className="operations-summary">
      <section className="panel"><span>Здоровые ноды</span><strong>{healthy} / {data.nodes.length}</strong></section>
      <section className="panel"><span>Свежие копии нод</span><strong>{backups} / {data.nodes.length}</strong></section>
      <section className="panel"><span>Сертификаты: требуют внимания</span><strong>{data.attention_certificates}</strong></section>
      <section className="panel"><span>Свободно на сервере панели</span><strong className={data.control_plane_free_bytes >= 0 && data.control_plane_free_bytes < 1024 ** 3 ? "operations-warning" : ""}>{bytes(data.control_plane_free_bytes)}</strong></section>
    </div>
    <section className="panel"><div className="panel-header"><div><h2>Резервная копия панели</h2><p>База данных, настройки, исходный код и исполняемые файлы.</p></div></div><div className="operations-content"><Backup backup={data.control_plane_backup} at={data.generated_at} /></div><p className="certificate-note">Копии сохраняются ежедневно локально, последние 7 проверенных копий удерживаются. Проверка базы выполняется в изоляции. Внешнее хранилище и аварийное восстановление сервера пока не настроены.</p></section>
    <section className="panel"><div className="panel-header"><div><h2>Проверка восстановления</h2><p>Пробный запуск сохранённой версии панели из резервной копии.</p></div></div><div className="operations-content"><RestoreCheck data={data} runningVersion={runningVersion} /></div><p className="certificate-note">Проверка базы и пробный запуск приложения — отдельные проверки. Результат относится к указанной копии и её версии. Восстановление на новом сервере и внешнее хранилище требуют отдельной проверки.</p></section>
    <section className="panel"><div className="panel-header"><div><h2>Ноды</h2><p>Архивы нод содержат регистрацию, настройки и ключи; в панели отображается только результат проверки.</p></div></div><div className="operations-nodes">{data.nodes.map(node => <article key={node.id} className="operations-node"><div><Link href={`/nodes/${node.id}/control`}><strong>{node.name}</strong></Link><p className={node.lifecycle.online && node.lifecycle.healthy && node.lifecycle.health_fresh ? "operations-good" : "operations-warning"}>{node.lifecycle.online ? node.lifecycle.healthy && node.lifecycle.health_fresh ? "В работе" : "Требует проверки" : "Нет связи"}</p><span>Поколения: {node.lifecycle.desired_generation} / {node.lifecycle.applied_generation} · Агент {node.lifecycle.agent_version ?? "—"}</span></div>{node.traffic_delivery && <div className="operations-backup"><strong>Учёт трафика</strong><span>Измерение: {when(node.traffic_delivery.recorded_at)}</span><span>Подтверждено панелью: {when(node.traffic_delivery.received_at)}</span></div>}<Backup backup={node.backup} at={data.generated_at} /><NodeRestoreCheck restore={node.restore_drill ?? null} backup={node.backup} at={data.generated_at} nodeID={node.id} /></article>)}</div></section>
    {(data.expired_certificates > 0 || data.expiring_certificates > 0 || data.failed_certificates > 0) && <section className="panel"><div className="panel-header"><div><h2>Сертификаты</h2><p>Истекли: {data.expired_certificates}. Истекают в течение 30 дней: {data.expiring_certificates}. Ошибки выпуска: {data.failed_certificates}.</p></div><Link href="/certificates" className="button primary">Проверить сертификаты</Link></div></section>}
    <p className="plan-muted">Обновлено: {when(data.generated_at)} (Москва).</p>
  </>;
}
