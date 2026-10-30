import {
  getControlPlaneHealth,
} from "@/lib/control-plane";

import {
  ru,
} from "@/lib/i18n/ru";

export const dynamic =
  "force-dynamic";

export default async function SettingsPage() {
  const health =
    await getControlPlaneHealth();

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            {ru.settings.eyebrow}
          </div>

          <h1>
            {ru.settings.title}
          </h1>

          <p>
            {ru.settings.subtitle}
          </p>
        </div>
      </header>

      <section className="panel">
        <dl className="settings-list">
          <div>
            <dt>
              {ru.settings.controlPlane}
            </dt>

            <dd>
              {health.version}
            </dd>
          </div>

          <div>
            <dt>
              {ru.settings.apiConnection}
            </dt>

            <dd>
              {ru.settings.localhostOnly}
            </dd>
          </div>

          <div>
            <dt>
              {ru.settings.browserAdminToken}
            </dt>

            <dd>
              {ru.settings.neverExposed}
            </dd>
          </div>

          <div>
            <dt>
              {ru.settings.sessionCookie}
            </dt>

            <dd>
              HttpOnly · Secure · SameSite Strict
            </dd>
          </div>

          <div>
            <dt>
              {ru.settings.agentConnectivity}
            </dt>

            <dd>
              {ru.settings.outboundModel}
            </dd>
          </div>

          <div>
            <dt>
              {ru.settings.webUI}
            </dt>

            <dd>
              v0.2.1 RU
            </dd>
          </div>
        </dl>
      </section>
    </>
  );
}
