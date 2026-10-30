import {
  StatusPill,
} from "@/components/status-pill";

import {
  getLifecycle,
  getNodes,
} from "@/lib/control-plane";

import {
  ru,
} from "@/lib/i18n/ru";

export const dynamic =
  "force-dynamic";

export default async function RecoveryPage() {
  const nodes =
    await getNodes();

  const items =
    await Promise.all(
      nodes.map(
        async (node) => ({
          node,
          lifecycle:
            await getLifecycle(
              node.id
            ),
        })
      )
    );

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            {ru.recovery.eyebrow}
          </div>

          <h1>
            {ru.recovery.title}
          </h1>

          <p>
            {ru.recovery.subtitle}
          </p>
        </div>
      </header>

      <section className="card-grid">
        {items.map(
          ({
            node,
            lifecycle,
          }) => (
            <article
              className="node-card"
              key={node.id}
            >
              <div className="node-card-top">
                <div>
                  <h3>
                    {node.name}
                  </h3>

                  <span className="mono">
                    {node.id.slice(
                      0,
                      8
                    )}
                  </span>
                </div>

                <StatusPill
                  value={
                    lifecycle.state
                  }
                />
              </div>

              <dl className="mini-details">
                <div>
                  <dt>
                    {ru.recovery.currentCore}
                  </dt>

                  <dd>
                    {lifecycle
                      .current_core_version ??
                      "—"}
                  </dd>
                </div>

                <div>
                  <dt>
                    {ru.recovery.lkg}
                  </dt>

                  <dd>
                    {lifecycle
                      .last_known_good_core_version ??
                      "—"}
                  </dd>
                </div>

                <div>
                  <dt>
                    {ru.recovery.rollback}
                  </dt>

                  <dd>
                    {lifecycle.rollback_ready
                      ? ru.common.ready
                      : ru.common.unavailable}
                  </dd>
                </div>

                <div>
                  <dt>
                    {ru.recovery.recovery}
                  </dt>

                  <dd>
                    {lifecycle.active_recovery
                      ? ru.recovery.active
                      : ru.recovery.idle}
                  </dd>
                </div>
              </dl>
            </article>
          )
        )}
      </section>
    </>
  );
}
