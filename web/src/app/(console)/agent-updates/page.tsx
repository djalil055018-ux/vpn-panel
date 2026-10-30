import { agentUpdaterInstallCommand } from "@/lib/node-runtime";
import { installationOrigin } from "@/lib/installation-origin";
import Link from "next/link";
import { randomUUID } from "crypto";
import { redirect } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { getAgentFleetStatus } from "@/lib/control-plane";
import { newerVersion, updateStatusLabels } from "@/lib/update-types";
import { UpdateButton, UpdateRefresh } from "@/components/update-controls";

export const dynamic = "force-dynamic";
export default async function AgentUpdatesPage() {
  const session = await requireSession();
  if (session.role === "monitor") redirect("/monitor");
  const status = await getAgentFleetStatus();
  const latest = status.releases.find(r => !r.revoked)?.version;
  const active = status.runs.find(r => r.status !== "completed");
  const names = new Map(status.nodes.map(n => [n.id, n.name]));
  const owner = session.role === "owner";
  const origin = installationOrigin(process.env.VPN_PLATFORM_PUBLIC_URL);
  return <><header className="page-header"><div><div className="eyebrow">Обновления</div><h1>Агенты нод</h1><p>Начните с одной ноды. После её успешного обновления остальные обновятся по очереди. Роутерные ноды исключены из обновлений по политике безопасности.</p></div><UpdateRefresh active={Boolean(active)}/></header>
    <section className="panel"><div className="panel-header"><div><h2>Последняя доступная версия: {latest ?? "нет опубликованной сборки"}</h2><p>Автоматическое продолжение: {status.policy.auto_spread ? "включено" : "выключено"}. Офлайн-ноды дождутся подключения; ошибка приостановит очередь.</p></div></div><div className="table-wrap"><table><thead><tr><th>Нода</th><th>Агент</th><th>Готовность</th><th>Действие</th></tr></thead><tbody>{status.nodes.map(node => <tr key={node.id}><td><Link href={`/nodes/${node.id}`}>{node.name}</Link></td><td>{node.agent_version ?? "Не установлен"}</td><td>{!node.agent_update_eligible ? "Исключена из обновлений политикой панели" : !node.registered ? "Ожидает регистрации" : !node.platform_supported ? "Платформа не поддерживается" : !node.online ? "Офлайн" : !node.updater_online ? "Нужно подключить модуль обновления" : "Готова к обновлению"}</td><td>{latest && (!node.agent_version || newerVersion(latest, node.agent_version)) ? <UpdateButton operation="agent-start" node={node.id} requestKey={randomUUID()} disabled={!owner || !node.agent_update_eligible || !node.registered || !node.online || !node.platform_supported || !node.updater_online || Boolean(active)}>Обновить до {latest}</UpdateButton> : node.registered ? "Актуальная версия" : "—"}</td></tr>)}</tbody></table></div></section>
    {status.runs.map(run => <section className="panel" key={run.id}><div className="panel-header"><div><h2>Версия {run.target_version} · {updateStatusLabels[run.status] ?? "Проверка состояния"}</h2><p>{new Date(run.created_at).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" })} МСК</p>{run.status === "paused" && <p>Проверьте ноду с ошибкой или незавершённой установкой перед продолжением.</p>}</div>{owner && run.status !== "completed" && <UpdateButton operation={run.status === "paused" ? "agent-resume" : "agent-pause"} id={run.id}>{run.status === "paused" ? "Продолжить очередь" : "Приостановить очередь"}</UpdateButton>}</div><div className="table-wrap"><table><thead><tr><th>Нода</th><th>С версии</th><th>Результат</th><th>Действие</th></tr></thead><tbody>{run.jobs.map(job => <tr key={job.id}><td>{names.get(job.node_id) ?? "Нода удалена"}</td><td>{job.from_version || "Неизвестна"}</td><td>{updateStatusLabels[job.status] ?? "Требуется проверка"}</td><td>{owner && job.status === "failed" && <UpdateButton operation="agent-retry" id={job.id}>Повторить после проверки ноды</UpdateButton>}</td></tr>)}</tbody></table></div></section>)}
    {owner && status.nodes.some(node => node.registered && !node.updater_online) && <section className="panel"><h2>Подключить автоматические обновления</h2><p>На каждой ноде без модуля обновления выполните эту команду через SSH от root. После подключения статус изменится автоматически. Новые ноды подключают модуль во время установки.</p><details><summary>Команда подключения</summary><pre className="code-block">{origin ? agentUpdaterInstallCommand(origin) : "В настройках установки не указан публичный HTTPS-адрес панели. Обратитесь к владельцу панели."}</pre></details></section>}
    {!status.runs.length && <p className="muted">Обновления ещё не запускались.</p>}</>;
}
