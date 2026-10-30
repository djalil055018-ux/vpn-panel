import type {
  Lifecycle,
  NodeRecord,
  VPNServiceRecord,
} from "@/lib/control-plane";

import {
  runtimeLabel,
  type NodeRuntime,
} from "@/lib/node-runtime";

import {
  generationPresentation,
  nodeHealthPresentation,
  servicePresentation,
  type ProtocolTone,
} from "@/lib/protocol-presentation";

function Tone({
  label,
  tone,
}: {
  label: string;
  tone: ProtocolTone;
}) {
  return (
    <span className={`status ${tone}`}>
      <span
        className="status-dot"
        aria-hidden="true"
      />
      {label}
    </span>
  );
}

export function ProtocolRuntimeSummary({
  node,
  lifecycle,
  runtime,
  services,
}: {
  node: NodeRecord;
  lifecycle: Lifecycle;
  runtime: NodeRuntime;
  services: VPNServiceRecord[];
}) {
  const health =
    nodeHealthPresentation(
      lifecycle
    );

  const generation =
    generationPresentation(
      node.desired_generation,
      node.applied_generation,
      lifecycle.registered
    );

  const agent =
    node.agent_version?.trim() ||
    lifecycle.agent_version?.trim() ||
    (lifecycle.registered
      ? "версия неизвестна"
      : "не зарегистрирован");

  const enabled =
    services.filter(
      (service) =>
        service.enabled
    ).length;

  return (
    <section className="panel protocol-runtime-summary">
      <div className="panel-header">
        <div>
          <div className="eyebrow">
            PROTOCOL STATUS
          </div>

          <h2>
            Состояние VPN-ноды
          </h2>

          <p>
            Runtime, Agent,
            поколение конфигурации
            и фактические типы
            клиентских профилей.
          </p>
        </div>

        <Tone
          label={health.label}
          tone={health.tone}
        />
      </div>

      <div className="protocol-runtime-grid">
        <div>
          <span>Runtime</span>
          <strong>
            {runtimeLabel(runtime)}
          </strong>
        </div>

        <div>
          <span>Agent</span>
          <strong>{agent}</strong>
        </div>

        <div>
          <span>
            Desired / applied
          </span>

          <Tone
            label={generation.label}
            tone={generation.tone}
          />
        </div>

        <div>
          <span>Сервисы</span>
          <strong>
            {enabled} включено ·{" "}
            {services.length} всего
          </strong>
        </div>
      </div>

      <p className="plan-muted protocol-generation-note">
        Generation относится ко всей
        ноде. Отдельной generation
        конкретного VPN-сервиса
        текущий API не предоставляет.
      </p>

      <div className="protocol-service-overview">
        {services.length === 0 ? (
          <p className="protocol-empty">
            VPN-сервисы на этой ноде
            ещё не созданы.
          </p>
        ) : (
          services.map(
            (service) => {
              const view =
                servicePresentation(
                  service,
                  runtime
                );

              return (
                <article
                  key={service.id}
                  className="protocol-service-overview-row"
                >
                  <div className="protocol-service-overview-head">
                    <div>
                      <strong>
                        {service.name}
                      </strong>

                      <span>
                        {view.label}
                      </span>
                    </div>

                    <Tone
                      label={
                        view.state.label
                      }
                      tone={
                        view.state.tone
                      }
                    />
                  </div>

                  <dl className="protocol-service-facts">
                    <div>
                      <dt>Endpoint</dt>
                      <dd>
                        {view.endpoint}
                      </dd>
                    </div>

                    <div>
                      <dt>Профиль</dt>
                      <dd>
                        {view.profile}
                      </dd>
                    </div>

                    <div>
                      <dt>Трафик</dt>
                      <dd>
                        {view.traffic}
                      </dd>
                    </div>

                    <div>
                      <dt>Agent</dt>
                      <dd>
                        {
                          view.agentRequirement
                        }
                      </dd>
                    </div>
                  </dl>
                </article>
              );
            }
          )
        )}
      </div>
    </section>
  );
}
