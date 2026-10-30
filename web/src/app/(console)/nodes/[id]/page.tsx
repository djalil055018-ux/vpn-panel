import Link from "next/link";
import { requireSession } from "@/lib/auth";
import { NodeDelete } from "@/components/node-delete";
import { NodeReboot } from "@/components/node-reboot";
import { runtimeLabel } from "@/lib/node-runtime";
import { agentSupportsNodeReboot } from "@/lib/node-runtime";
import { nodeMetricsEmptyMessage } from "@/lib/node-metrics-presentation";

import {
  StatusPill,
} from "@/components/status-pill";

import {
  getDeployments,
  getDiagnostics,
  getNode,
  getNodeMetrics,
} from "@/lib/control-plane";
import type { NodeMetricPoint } from "@/lib/control-plane";

export const dynamic =
  "force-dynamic";

function value(
  input:
    string |
    number |
    undefined
) {
  return input ??
    "—";
}

function bytes(input: number | undefined) {
  if (input === undefined) return "—";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let value = input;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function percent(used: number, total: number) {
  return total > 0 ? Math.min(100, Math.max(0, used * 100 / total)) : 0;
}

function Sparkline({ points, value }: { points: NodeMetricPoint[]; value: (point: NodeMetricPoint) => number }) {
  if (points.length < 2) return <div className="metrics-empty">Для графика нужны минимум две точки за выбранный период.</div>;
  const values = points.map(value);
  const maximum = Math.max(1, ...values);
  const line = values.map((item, index) => `${(index * 100 / (values.length - 1)).toFixed(2)},${(32 - item * 30 / maximum).toFixed(2)}`).join(" ");
  return <svg className="metrics-sparkline" viewBox="0 0 100 34" preserveAspectRatio="none" role="img" aria-label="График за выбранный период"><polyline points={line} /></svg>;
}

export default async function NodePage({
  params,
  searchParams,
}: {
  params:
    Promise<{
      id: string;
    }>;
  searchParams: Promise<{ range?: string }>;
}) {
  const { id } =
    await params;
  const requestedRange = (await searchParams).range;
  const range = (["1h", "24h", "7d", "30d"].includes(requestedRange ?? "") ? requestedRange : "24h") as "1h" | "24h" | "7d" | "30d";

  const [
    detail,
    diagnostics,
    deployments,
    metrics,
  ] =
    await Promise.all([
      getNode(id),
      getDiagnostics(id),
      getDeployments(id),
      getNodeMetrics(id, range),
    ]);

  const {
    node,
    runtime,
    lifecycle,
  } = detail;
  const latest = metrics.points.at(-1);
  const session = await requireSession();
  const deleted = node.status === "retired";

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            NODE
          </div>
          <h1>
            {node.name}
          </h1>
          <p className="mono">
            {node.id}
          </p>
        </div>

        <div className="header-actions">
        <StatusPill
          value={lifecycle.state}
        />

        {!deleted && session.role === "owner" && <NodeDelete id={id} name={node.name} online={lifecycle.online} decommissioning={node.status === "decommissioning"} desiredGeneration={lifecycle.desired_generation} appliedGeneration={lifecycle.applied_generation} />}
        {!deleted && session.role === "owner" && <NodeReboot id={id} name={node.name} disabled={!agentSupportsNodeReboot(lifecycle.agent_version ?? node.agent_version) || !lifecycle.online || !lifecycle.healthy || !lifecycle.health_fresh || lifecycle.desired_generation !== lifecycle.applied_generation || node.status === "decommissioning"} disabledReason={!agentSupportsNodeReboot(lifecycle.agent_version ?? node.agent_version) ? "Установите агент с поддержкой перезагрузки" : undefined} />}
        {!deleted && <Link
          href={`/nodes/${id}/control`}
          className="button primary"
        >
          Control Center
        </Link>}
      </div>
      </header>

      {deleted && <section className="panel"><p>Нода удалена. Доступ агента отозван. Ниже сохранены последние сведения и история работы.</p><Link href="/nodes?deleted=true" className="button">Удалённые ноды</Link></section>}
      <section className="metric-grid">
        <article className="metric-card">
          <span>Ядро</span>
          <strong className="metric-version">
            {value(
              runtime.current_core_version
            )}
          </strong>
          <small>
            Текущая версия {runtimeLabel(detail.node.runtime_core ?? "xray")}
          </small>
        </article>

        <article className="metric-card">
          <span>LKG</span>
          <strong className="metric-version">
            {value(
              runtime
                .last_known_good_core_version
            )}
          </strong>
          <small>
            Последняя стабильная версия ядра
          </small>
        </article>

        <article className="metric-card">
          <span>Поколение</span>
          <strong>
            {node.applied_generation}
          </strong>
          <small>
            desired{" "}
            {node.desired_generation}
          </small>
        </article>

        <article className="metric-card">
          <span>Snapshots</span>
          <strong>
            {runtime.snapshot_count}
          </strong>
          <small>
            rollback{" "}
            {runtime.rollback_ready
              ? "ready"
              : "unavailable"}
          </small>
        </article>
      </section>

      <section className="panel node-metrics">
        <div className="panel-header">
          <div><h2>Ресурсы ноды</h2><p>CPU, память, диск и сетевые счётчики от агента. Хранение — 31 день.</p></div>
          <nav className="metrics-ranges" aria-label="Период метрик">{(["1h", "24h", "7d", "30d"] as const).map(item => <Link key={item} href={`/nodes/${id}?range=${item}`} className={item === range ? "button primary" : "button ghost"}>{item}</Link>)}</nav>
        </div>
        {latest ? <>
          <div className="metrics-summary">
            <article><span>CPU</span><strong>{latest.cpu_percent.toFixed(1)}%</strong><small>load {latest.load_1.toFixed(2)}</small></article>
            <article><span>Память</span><strong>{percent(latest.memory_used_bytes, latest.memory_total_bytes).toFixed(1)}%</strong><small>{bytes(latest.memory_used_bytes)} / {bytes(latest.memory_total_bytes)}</small></article>
            <article><span>Диск</span><strong>{percent(latest.disk_used_bytes, latest.disk_total_bytes).toFixed(1)}%</strong><small>{bytes(latest.disk_used_bytes)} / {bytes(latest.disk_total_bytes)}</small></article>
            <article><span>Сеть с запуска</span><strong>↓ {bytes(latest.network_rx_bytes)}</strong><small>↑ {bytes(latest.network_tx_bytes)}</small></article>
          </div>
          <div className="metrics-charts">
            <article><header><strong>CPU</strong><span>{metrics.points.length} точек</span></header><Sparkline points={metrics.points} value={point => point.cpu_percent} /></article>
            <article><header><strong>Память</strong><span>{range}</span></header><Sparkline points={metrics.points} value={point => percent(point.memory_used_bytes, point.memory_total_bytes)} /></article>
            <article><header><strong>Диск</strong><span>{range}</span></header><Sparkline points={metrics.points} value={point => percent(point.disk_used_bytes, point.disk_total_bytes)} /></article>
          </div>
        </> : <div className="metrics-empty">{nodeMetricsEmptyMessage(node, lifecycle)}</div>}
      </section>

      <div className="two-column">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>
                Runtime
              </h2>
              <p>
                Agent and data-plane state
              </p>
            </div>
          </div>

          <dl className="detail-grid">
            <div>
              <dt>Жизненный цикл</dt>
              <dd>
                <StatusPill
                  value={
                    lifecycle.state
                  }
                />
              </dd>
            </div>

            <div>
              <dt>Состояние</dt>
              <dd>
                <StatusPill
                  value={
                    lifecycle.healthy
                      ? "healthy"
                      : "degraded"
                  }
                />
              </dd>
            </div>

            <div>
              <dt>Агент</dt>
              <dd>
                {value(
                  node.agent_version
                )}
              </dd>
            </div>

            <div>
              <dt>Operating System</dt>
              <dd>
                {value(node.os_name)}
                {" "}
                {value(node.os_version)}
              </dd>
            </div>

            <div>
              <dt>Архитектура</dt>
              <dd>
                {value(
                  node.architecture
                )}
              </dd>
            </div>

            <div>
              <dt>Generation Drift</dt>
              <dd className="mono">
                {lifecycle
                  .generation_drift}
              </dd>
            </div>

            <div>
              <dt>Bootstrap</dt>
              <dd>
                {lifecycle
                  .bootstrap_consumed
                  ? "Consumed"
                  : "Available"}
              </dd>
            </div>

            <div>
              <dt>Active Recovery</dt>
              <dd>
                {lifecycle
                  .active_recovery
                  ? "Yes"
                  : "No"}
              </dd>
            </div>

            <div>
              <dt>
                Latest Snapshot
              </dt>
              <dd className="mono">
                {value(
                  runtime
                    .latest_snapshot_id
                )}
              </dd>
            </div>

            <div>
              <dt>
                Latest Deployment
              </dt>
              <dd>
                {value(
                  lifecycle
                    .latest_deployment_status
                )}
              </dd>
            </div>
          </dl>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>
                Diagnostics
              </h2>
              <p>
                Generated from live node facts
              </p>
            </div>

            <StatusPill
              value={
                diagnostics.overall
              }
            />
          </div>

          <div className="checks">
            {diagnostics.checks.map(
              (check) => (
                <div
                  key={check.code}
                  className="check-row"
                >
                  <StatusPill
                    value={
                      check.status
                    }
                  />

                  <div>
                    <strong>
                      {check.code
                        .replaceAll(
                          "_",
                          " "
                        )}
                    </strong>
                    <span>
                      {check.message}
                    </span>
                  </div>
                </div>
              )
            )}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>
              Recent Deployments
            </h2>
            <p>
              Reconcile and core rollout history
            </p>
          </div>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Поколение</th>
                <th>Состояние</th>
                <th>Requested</th>
                <th>Applied</th>
                <th>Previous</th>
              </tr>
            </thead>

            <tbody>
              {deployments
                .slice(0, 10)
                .map(
                  (deployment) => (
                    <tr
                      key={
                        deployment.id
                      }
                    >
                      <td className="mono">
                        {
                          deployment
                            .generation
                        }
                      </td>
                      <td>
                        <StatusPill
                          value={
                            deployment
                              .status
                          }
                        />
                      </td>
                      <td className="mono">
                        {value(
                          deployment
                            .requested_core_version
                        )}
                      </td>
                      <td className="mono">
                        {value(
                          deployment
                            .applied_core_version
                        )}
                      </td>
                      <td className="mono">
                        {value(
                          deployment
                            .previous_core_version
                        )}
                      </td>
                    </tr>
                  )
                )}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
