"use client";
import { nodeInstallCommand, runtimeLabel, type NodeRuntime } from "@/lib/node-runtime";

import Link from "next/link";
import { NavIcon } from "@/components/ui/nav-icon";

import {
  useActionState,
  useEffect,
  useState,
} from "react";

import {
  createNodeAction,
  getNodeOnboardingStatusAction,
  type CreateNodeActionState,
  type NodeOnboardingStatus,
} from "@/app/node-actions";

type TenantOption = {
  id: string;
  label: string;
};

const initialState:
  CreateNodeActionState = {
    ok: false,
    title: "",
    message: "",
  };

function formatLastSeen(
  value?: string
) {
  if (!value) {
    return "—";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return value;
  }

  return new Intl.DateTimeFormat(
    "ru-RU",
    {
      dateStyle: "medium",
      timeStyle: "medium",
    }
  ).format(date);
}

async function copyText(
  value: string
) {
  await navigator.clipboard.writeText(
    value
  );
}

export function AddNodeForm({
  tenants,
  installationOrigin,
  defaultRuntime = "xray",
}: {
  tenants: TenantOption[];
  installationOrigin: string | null;
  defaultRuntime?: NodeRuntime;
}) {
  const [
    state,
    action,
    pending,
  ] =
    useActionState(
      createNodeAction,
      initialState
    );
  const installCommand = state.node && installationOrigin ? nodeInstallCommand(state.node.runtimeCore, state.node.id, installationOrigin) : "";

  const [
    tokenCopied,
    setTokenCopied,
  ] =
    useState(false);

  const [
    commandCopied,
    setCommandCopied,
  ] =
    useState(false);

  const [
    onboarding,
    setOnboarding,
  ] =
    useState<
      NodeOnboardingStatus | null
    >(null);

  const [
    pollingError,
    setPollingError,
  ] =
    useState("");

  useEffect(
    () => {
      const nodeID =
        state.node?.id ?? "";

      if (
        !state.ok ||
        !nodeID
      ) {
        return;
      }

      let cancelled = false;
      let timer:
        number | undefined;

      async function poll() {
        try {
          const result =
            await getNodeOnboardingStatusAction(
              nodeID
            );

          if (cancelled) {
            return;
          }

          if (!result.ok) {
            setPollingError(
              result.message
            );
          } else {
            setPollingError("");
            setOnboarding(
              result
            );
          }

          if (
            result.ok &&
            result.ready
          ) {
            return;
          }
        } catch {
          if (!cancelled) {
            setPollingError(
              "Не удалось обновить состояние сервера."
            );
          }
        }

        if (!cancelled) {
          timer =
            window.setTimeout(
              poll,
              3000
            );
        }
      }

      void poll();

      return () => {
        cancelled = true;

        if (timer) {
          window.clearTimeout(
            timer
          );
        }
      };
    },
    [
      state.ok,
      state.node?.id,
    ]
  );

  async function copyToken() {
    if (
      !state.bootstrapToken
    ) {
      return;
    }

    try {
      await copyText(
        state.bootstrapToken
      );

      setTokenCopied(true);

      window.setTimeout(
        () => {
          setTokenCopied(false);
        },
        2000
      );
    } catch {
      setTokenCopied(false);
    }
  }

  async function copyCommand() {
    try {
      await copyText(
        installCommand
      );

      setCommandCopied(true);

      window.setTimeout(
        () => {
          setCommandCopied(false);
        },
        2000
      );
    } catch {
      setCommandCopied(false);
    }
  }

  if (!installationOrigin) return <section className="panel onboarding-panel"><h2>Настройте адрес панели</h2><p>Для подключения серверов нужен публичный HTTPS-адрес этой панели. Обратитесь к владельцу панели, чтобы завершить её установку.</p></section>;

  if (
    state.ok &&
    state.bootstrapToken &&
    state.node
  ) {
    const connected =
      onboarding?.ready ===
      true;

    return (
      <><ol className="setup-progress" aria-label="Шаги подключения"><li><span>✓</span><strong>Параметры сервера</strong></li><li aria-current={!connected ? "step" : undefined}><span>{connected ? "✓" : "02"}</span><strong>Установка агента</strong></li><li aria-current={connected ? "step" : undefined}><span>{connected ? "✓" : "03"}</span><strong>Проверка связи</strong></li></ol><section className="panel add-node-success onboarding-panel">
        <div
          className={
            connected
              ? "success-mark"
              : "onboarding-wait-mark"
          }
        >
          {connected
            ? "✓"
            : "…"}
        </div>

        <div>
          <div className="eyebrow">
            {connected
              ? "АГЕНТ ГОТОВ"
              : "СЕРВЕР ДОБАВЛЕН"}
          </div>

          <h2>
            {state.node.name}
          </h2>
          <p>Ядро: {runtimeLabel(state.node.runtimeCore)}</p>

          <p>
            ID:{" "}
            <span className="mono">
              {state.node.id}
            </span>
          </p>
        </div>

        <div className="onboarding-steps">
          <article className="onboarding-step">
            <div className="onboarding-step-number">
              1
            </div>

            <div className="onboarding-step-body">
              <strong>
                Токен первичной регистрации
              </strong>

              <p>
                Он показывается только в текущем сеансе. Не отправляйте его в чат и не сохраняйте в общедоступных местах.
              </p>

              {onboarding?.bootstrapConsumed ? (
                <p>Токен уже использован. Для повтора установки этого сервера используйте ту же команду — повторный ввод токена не потребуется.</p>
              ) : <div className="token-row">
                <code>
                  {state.bootstrapToken}
                </code>

                <button
                  type="button"
                  className="button"
                  onClick={copyToken}
                >
                  {tokenCopied
                    ? "Скопировано"
                    : "Копировать"}
                </button>
              </div>}
            </div>
          </article>

          <article className="onboarding-step">
            <div className="onboarding-step-number">
              2
            </div>

            <div className="onboarding-step-body">
              <strong>
                Выполните команду на сервере
              </strong>

              <p>
                Запустите команду от root на сервере Ubuntu 24.04 x86_64 с Python 3. Установщик отдельно запросит токен скрытым вводом, проверит совместимость выбранного ядра и подтвердит подключение. При ошибке установщик откатит заменённые файлы. Если регистрация уже прошла, повторите эту же команду после завершения отката. Она проверит, что сервер подключается к нужной записи в панели.
              </p>

              <div className="token-row onboarding-command">
                <code>
                  {installCommand}
                </code>

                <button
                  type="button"
                  className="button"
                  onClick={copyCommand}
                >
                  {commandCopied
                    ? "Скопировано"
                    : "Копировать команду"}
                </button>
              </div>
            </div>
          </article>

          <article className="onboarding-step">
            <div className="onboarding-step-number">
              3
            </div>

            <div className="onboarding-step-body">
              <strong>
                {onboarding?.label ?? "Ожидаем подключение"}
              </strong>

              <p>
                {onboarding?.message ?? "Панель автоматически проверяет регистрацию каждые 3 секунды."}
              </p>

              <div className="onboarding-status-grid">
                <div>
                  <span>
                    Состояние
                  </span>
                  <strong>
                    {onboarding?.label ?? "Ожидание"}
                  </strong>
                </div>

                <div>
                  <span>
                    Агент
                  </span>
                  <strong>
                    {onboarding?.agentVersion ??
                      "—"}
                  </strong>
                </div>

                <div>
                  <span>
                    ОС
                  </span>
                  <strong>
                    {onboarding?.osName
                      ? `${onboarding.osName} ${onboarding.osVersion ?? ""}`.trim()
                      : "—"}
                  </strong>
                </div>

                <div>
                  <span>
                    Архитектура
                  </span>
                  <strong>
                    {onboarding?.architecture ??
                      "—"}
                  </strong>
                </div>

                <div>
                  <span>
                    Последняя связь
                  </span>
                  <strong>
                    {formatLastSeen(
                      onboarding?.lastSeenAt
                    )}
                  </strong>
                </div>

                <div>
                  <span>
                    Токен использован
                  </span>
                  <strong>
                    {onboarding?.bootstrapConsumed
                      ? "Да"
                      : "Нет"}
                  </strong>
                </div>
              </div>

              {pollingError && (
                <div className="action-result error-result onboarding-error">
                  <strong>
                    Ошибка обновления статуса
                  </strong>

                  <p>
                    {pollingError}
                  </p>
                </div>
              )}

              {!connected && (
                <div className="onboarding-pulse">
                  <span />
                  Автоматическая проверка активна
                </div>
              )}

              <div className="onboarding-actions">
                  <Link
                    href={`/nodes/${state.node.id}`}
                    className="button primary"
                  >
                    Открыть сервер
                  </Link>

                  <Link
                    href="/nodes"
                    className="button"
                  >
                    Все серверы
                  </Link>
              </div>
            </div>
          </article>
        </div>
      </section></>
    );
  }

  return (
    <><ol className="setup-progress" aria-label="Шаги подключения"><li aria-current="step"><span>01</span><strong>Параметры сервера</strong></li><li><span>02</span><strong>Установка агента</strong></li><li><span>03</span><strong>Проверка связи</strong></li></ol><div className="enrollment-layout"><section className="panel add-node-panel">
      <div className="panel-header">
        <div>
          <h2>
            Расскажите о сервере
          </h2>

          <p>
            Выберите ядро и имя. На следующем шаге получите команду подключения.
          </p>
        </div>
      </div>

      <form
        action={action}
        className="add-node-form"
      >
        <fieldset className="runtime-picker"><legend>Выберите VPN-ядро</legend><p>Для каждого ядра подключается отдельный сервер.</p><div className="runtime-options">{[
          { value: "xray", label: "Xray", hint: "VLESS, Trojan, Shadowsocks", tag: "Универсальный" },
          { value: "hysteria2", label: "Hysteria 2", hint: "Быстрый транспорт UDP / TLS", tag: "QUIC" },
          { value: "amneziawg", label: "AmneziaWG", hint: "Версии 1.0, 1.5, 2.0, 3.0 и 3.1", tag: "5 версий" },
          { value: "wireguard", label: "WireGuard", hint: "Нативный VPN-туннель", tag: "Native" },
          { value: "openvpn", label: "OpenVPN", hint: "TCP / UDP и сертификаты", tag: "TLS" },
          { value: "pptp", label: "PPTP", hint: "Для совместимости со старыми устройствами", tag: "Legacy" },
        ].map(runtime => <label className="runtime-option" key={runtime.value}><input type="radio" name="runtime_core" value={runtime.value} defaultChecked={defaultRuntime === runtime.value} required /><span className="runtime-option-copy"><strong>{runtime.label}</strong><small>{runtime.hint}</small></span><span className="runtime-chip">{runtime.tag}</span></label>)}</div></fieldset>
        <label>
          Название сервера

          <input
            name="name"
            required
            maxLength={80}
            placeholder="Например: NL-AMS-01"
            autoComplete="off"
          />
        </label>

        <label>
          Рабочее пространство

          <select
            name="tenant_id"
            required
            defaultValue={
              tenants.length === 1
                ? tenants[0].id
                : ""
            }
          >
            {tenants.length !== 1 && (
              <option
                value=""
                disabled
              >
                Выберите владельца
              </option>
            )}

            {tenants.map(
              (tenant) => (
                <option
                  key={tenant.id}
                  value={tenant.id}
                >
                  {tenant.label}
                </option>
              )
            )}
          </select>

          <small>
            Клиенты и настройки этого сервера будут доступны выбранному владельцу.
          </small>
        </label>

        {tenants.length === 0 && (
          <div className="action-result error-result">
            <strong>
              Владелец не найден
            </strong>

            <p>
              В контуре управления пока нет доступных владельцев.
            </p>
          </div>
        )}

        <div className="token-warning">
          <strong>
            Одноразовый токен первичной регистрации
          </strong>

          <p>
            После создания токен будет показан только в текущем сеансе мастера подключения.
          </p>
        </div>

        <button
          type="submit"
          className="button primary"
          disabled={
            pending ||
            tenants.length === 0
          }
        >
          {pending
            ? "Создание..."
            : "Продолжить →"}
        </button>
      </form>

      {state.title && (
        <div
          className={
            state.ok
              ? "action-result success-result"
              : "action-result error-result"
          }
        >
          <strong>
            {state.title}
          </strong>

          <p>
            {state.message}
          </p>
        </div>
      )}
    </section><aside className="enrollment-guide"><span className="guide-icon"><NavIcon name="nodes" width={25} height={25} /></span><h2>Три шага — и сервер в сети</h2><p>Установка займёт несколько минут. Статус подключения появится прямо в этой панели.</p><ol><li><strong>Создайте запись</strong><span>Укажите понятное имя, чтобы легко находить сервер.</span></li><li><strong>Скопируйте команду</strong><span>Выполните её в терминале сервера от root. Затем введите одноразовый токен.</span></li><li><strong>Дождитесь подтверждения</strong><span>Когда агент выйдет на связь, можно будет настроить VPN и доступ клиентов.</span></li></ol><div className="requirements-note"><strong>Подготовьте сервер</strong><p>Ubuntu 24.04 · x86_64 · Python 3<br />Доступ root и подключение к интернету.</p></div></aside></div></>
  );
}
