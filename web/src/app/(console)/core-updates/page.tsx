import { AmneziaWGReleaseManager } from "@/components/amneziawg-manager";
import { WireGuardReleaseManager } from "@/components/wireguard-setup";
import Link from "next/link";
import { randomUUID } from "crypto";
import { redirect } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { getNodes, getNode } from "@/lib/control-plane";
import { newerVersion, updateStatusLabels, type XrayReleaseChoice } from "@/lib/update-types";
import { UpdateButton, UpdateRefresh, XrayApproval, XrayInstall } from "@/components/update-controls";
import { PPTPReleaseManager } from "@/components/pptp-setup";
import { OpenVPNReleaseManager } from "@/components/openvpn-setup";
import {
  StatusPill,
} from "@/components/status-pill";
import { HysteriaReleaseManager } from "@/components/hysteria-setup";

import {
  getCoreReleases,
} from "@/lib/control-plane";

import {
  ru,
} from "@/lib/i18n/ru";

export const dynamic =
  "force-dynamic";

export default async function CoreUpdatesPage() {
  const session = await requireSession();
  if (session.role === "monitor") redirect("/monitor");
  const [releases, nodes] = await Promise.all([getCoreReleases(), getNodes()]);
  const xray: XrayReleaseChoice[] = releases.filter(r => (r.type ?? r.core_type) === "xray" && r.id && !r.revoked && r.os === "linux" && r.architecture === "amd64").map(r => ({ id: r.id!, version: r.version, approved: Boolean(r.approved), prerelease: Boolean(r.upstream_prerelease) })).sort((a, b) => newerVersion(a.version, b.version) ? -1 : newerVersion(b.version, a.version) ? 1 : 0);
  const details = await Promise.allSettled(nodes.filter(n => (n.runtime_core ?? "xray") === "xray").map(n => getNode(n.id)));
  const xrayNodes = details.flatMap(result => result.status === "fulfilled" ? [result.value] : []);
  const updating = xrayNodes.some(n => n.lifecycle.desired_generation !== n.lifecycle.applied_generation);

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            {ru.coreUpdates.eyebrow}
          </div>

          <h1>
            {ru.coreUpdates.title}
          </h1>

          <p>
            {ru.coreUpdates.subtitle}
          </p>
        </div>

        <div className="header-count">
          {releases.length}
        </div>
      </header>

      <section className="panel"><div className="panel-header"><div><h2>Обновить Xray</h2><p>Проверьте новые версии, одобрите нужный выпуск и запустите установку на выбранной ноде.</p><p>Источник: <a href="https://github.com/XTLS/Xray-core/releases" target="_blank" rel="noreferrer">официальные выпуски Xray-core</a>. Предварительные выпуски отмечены отдельно.</p></div><UpdateRefresh active={updating}/></div><div className="plan-form"><UpdateButton operation="xray-discover">Проверить новые версии Xray</UpdateButton>{xray[0] && <p>Последняя добавленная версия: <strong>{xray[0].version}</strong>{xray[0].prerelease ? " · предварительный выпуск" : ""}{xray[0].approved ? " · одобрена" : " · ожидает одобрения"}</p>}{xray.filter(r => !r.approved).slice(0, 3).map(release => <XrayApproval key={release.id} release={release}/>)}</div></section>
      <section className="panel"><div className="panel-header"><div><h2>Xray на нодах</h2><p>Панель проверит совместимость и состояние ноды, сохранит выбранную версию и запустит установку. Результат появится в этой таблице.</p></div><Link className="button" href="/agent-updates">Обновления агентов</Link></div><div className="table-wrap"><table><thead><tr><th>Нода</th><th>Установлено</th><th>Состояние</th><th>Обновление</th></tr></thead><tbody>{xrayNodes.map(({node, lifecycle}) => {
        const choices = xray.filter(r => r.approved && newerVersion(r.version, lifecycle.current_core_version ?? ""));
        const busy = lifecycle.desired_generation !== lifecycle.applied_generation;
        const ready = lifecycle.registered && lifecycle.online && lifecycle.healthy && lifecycle.health_fresh && !busy && !lifecycle.active_recovery;
        // Keep retries stable within one deployment; a new lifecycle needs a new request and fresh feedback.
        return <tr key={node.id} id={`node-${node.id}`}><td><Link href={`/nodes/${node.id}`}>{node.name}</Link></td><td>{lifecycle.current_core_version ?? "Не установлено"}</td><td>{!lifecycle.registered ? "Ожидает регистрации" : !lifecycle.online ? "Офлайн" : !lifecycle.health_fresh ? "Ожидает проверки" : busy ? updateStatusLabels[lifecycle.latest_deployment_status ?? "pending"] ?? "Обновляется" : !lifecycle.healthy ? "Нужна проверка" : lifecycle.latest_deployment_status === "rolled_back" ? "Выполнен откат" : "Работает"}<br/><Link href={`/nodes/${node.id}/control`}>Подробности и восстановление</Link></td><td><XrayInstall key={`${node.id}:${lifecycle.desired_generation}:${lifecycle.applied_generation}:${lifecycle.latest_deployment_status ?? "none"}`} node={node.id} releases={choices} requestKey={randomUUID()} disabled={!ready}/></td></tr>;
      })}</tbody></table></div>{!xrayNodes.length && <p>Ноды с Xray пока отсутствуют.</p>}{details.some(result => result.status === "rejected") && <p role="status">Часть нод временно не ответила. Обновите состояние.</p>}</section>
      <HysteriaReleaseManager /><OpenVPNReleaseManager /><PPTPReleaseManager /><WireGuardReleaseManager /><AmneziaWGReleaseManager />
      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{ru.coreUpdates.version}</th>
                <th>{ru.coreUpdates.core}</th>
                <th>{ru.coreUpdates.channel}</th>
                <th>{ru.coreUpdates.approved}</th>
                <th>{ru.coreUpdates.revoked}</th>
                <th>{ru.coreUpdates.platform}</th>
              </tr>
            </thead>

            <tbody>
              {releases.map(
                (release, index) => (
                  <tr
                    key={
                      release.id ??
                      `${release.version}-${index}`
                    }
                  >
                    <td className="mono">
                      {release.version}
                    </td>

                    <td>
                      {release.type ??
                        release.core_type ??
                        "xray"}
                    </td>

                    <td>
                      <StatusPill
                        value={
                          release.channel ??
                          "unknown"
                        }
                      />
                    </td>

                    <td>
                      {release.approved
                        ? ru.common.yes
                        : ru.common.no}
                    </td>

                    <td>
                      {release.revoked
                        ? ru.common.yes
                        : ru.common.no}
                    </td>

                    <td>
                      {release.os ?? "—"}
                      {" / "}
                      {release.architecture ??
                        "—"}
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
