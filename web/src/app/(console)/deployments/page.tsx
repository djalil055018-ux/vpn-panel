import {
  StatusPill,
} from "@/components/status-pill";

import {
  getDeployments,
  getNodes,
} from "@/lib/control-plane";

import {
  ru,
} from "@/lib/i18n/ru";

export const dynamic =
  "force-dynamic";

export default async function DeploymentsPage() {
  const nodes =
    await getNodes();

  const groups =
    await Promise.all(
      nodes.map(
        async (node) => ({
          node,
          deployments:
            await getDeployments(
              node.id
            ),
        })
      )
    );

  const rows =
    groups
      .flatMap(
        ({ node, deployments }) =>
          deployments.map(
            (deployment) => ({
              ...deployment,
              nodeName: node.name,
            })
          )
      )
      .sort(
        (a, b) =>
          b.generation -
          a.generation
      );

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            {ru.deployments.eyebrow}
          </div>

          <h1>
            {ru.deployments.title}
          </h1>

          <p>
            {ru.deployments.subtitle}
          </p>
        </div>
      </header>

      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{ru.nodes.name}</th>
                <th>{ru.nodes.generation}</th>
                <th>{ru.nodes.lifecycle}</th>
                <th>{ru.node.previous}</th>
                <th>{ru.node.requested}</th>
                <th>{ru.node.applied}</th>
              </tr>
            </thead>

            <tbody>
              {rows.map(
                (row) => (
                  <tr key={row.id}>
                    <td>
                      {row.nodeName}
                    </td>

                    <td className="mono">
                      {row.generation}
                    </td>

                    <td>
                      <StatusPill
                        value={row.status}
                      />
                    </td>

                    <td className="mono">
                      {row.previous_core_version ??
                        "—"}
                    </td>

                    <td className="mono">
                      {row.requested_core_version ??
                        "—"}
                    </td>

                    <td className="mono">
                      {row.applied_core_version ??
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
