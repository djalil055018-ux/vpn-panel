"use client";

import {
  useState,
  useTransition,
} from "react";

import {
  QRCodeSVG,
} from "qrcode.react";

import {
  createVPNClientSubscriptionAction,
  getVPNClientSubscriptionAction,
  rotateVPNClientSubscriptionAction,
  type SubscriptionActionResult,
} from "@/app/client-actions";

import {
  ClientConnection,
} from "@/components/client-connection";

const emptyResult:
  SubscriptionActionResult = {
    ok: true,
    exists: false,
    message: "",
    subscription: null,
  };

export function ClientSubscription({
  clientID,
  connectionRevision,
}: {
  clientID: string;
  connectionRevision: string;
}) {
  const [
    pending,
    startTransition,
  ] =
    useTransition();

  const [
    loaded,
    setLoaded,
  ] =
    useState(false);

  const [
    result,
    setResult,
  ] =
    useState<
      SubscriptionActionResult
    >(emptyResult);

  const [
    copied,
    setCopied,
  ] =
    useState(false);
  const [reserveCopyStatus, setReserveCopyStatus] = useState("");

  function load() {
    startTransition(
      async () => {
        const next =
          await getVPNClientSubscriptionAction(
            clientID
          );

        setResult(next);
        setLoaded(true);
      }
    );
  }

  function create() {
    startTransition(
      async () => {
        const next =
          await createVPNClientSubscriptionAction(
            clientID
          );

        setResult(next);
        setLoaded(true);
      }
    );
  }

  function rotate() {
    if (
      !window.confirm(
        "Перевыпустить ссылку? Старая VPN-подписка сразу перестанет работать."
      )
    ) {
      return;
    }

    startTransition(
      async () => {
        const next =
          await rotateVPNClientSubscriptionAction(
            clientID
          );

        setResult(next);
        setLoaded(true);
        setCopied(false);
        setReserveCopyStatus("");
      }
    );
  }

  async function copy() {
    const url =
      result.subscription?.url;

    if (!url) {
      return;
    }

    await navigator.clipboard.writeText(
      url
    );

    setCopied(true);

    window.setTimeout(
      () => {
        setCopied(false);
      },
      1800
    );
  }

  const subscription =
    result.subscription;
  const reserve = subscription?.reserve;

  async function copyReserve() {
    if (!reserve) return;
    if (Date.parse(reserve.expires_at) <= Date.now()) {
      setReserveCopyStatus("Время тестового адреса истекло. Обновите данные подписки.");
      return;
    }
    try {
      await navigator.clipboard.writeText(reserve.url);
      setReserveCopyStatus("Резервная ссылка скопирована");
    } catch {
      setReserveCopyStatus("Выделите и скопируйте резервную ссылку ниже.");
    }
  }

  return (
    <div className="connection-control">
      {!loaded && (
        <button
          type="button"
          className="button primary"
          onClick={load}
          disabled={pending}
        >
          {pending
            ? "Получаем..."
            : "VPN-подписка"}
        </button>
      )}

      {loaded &&
        !subscription && (
          <div className="connection-card">
            <div className="connection-card-head">
              <div>
                <strong>
                  VPN-подписка
                </strong>
                <span>
                  {result.message}
                </span>
              </div>
            </div>

            {result.ok &&
              !result.exists && (
                <div className="connection-buttons">
                  <button
                    type="button"
                    className="button primary"
                    onClick={create}
                    disabled={pending}
                  >
                    {pending
                      ? "Создаём..."
                      : "Создать подписку"}
                  </button>
                </div>
              )}
          </div>
        )}

      {subscription && (
        <div className="connection-card">
          <div className="connection-card-head">
            <div>
              <strong>
                VPN-подписка
              </strong>

              <span>
                Статус: активна
                {" · "}
                версия ссылки{" "}
                {subscription.token_version}
              </span>
            </div>
          </div>

          <code className="connection-uri">
            {subscription.url}
          </code>

          <div className="connection-buttons">
            <button
              type="button"
              className="button primary"
              onClick={copy}
            >
              {copied
                ? "Скопировано"
                : "Скопировать подписку"}
            </button>

            <button
              type="button"
              className="button ghost"
              onClick={rotate}
              disabled={pending}
            >
              {pending
                ? "Выполняется..."
                : "Перевыпустить"}
            </button>
          </div>

          {result.message && (
            <small
              className={
                result.ok
                  ? "client-action-message success"
                  : "client-action-message error"
              }
            >
              {result.message}
            </small>
          )}

          {reserve && <details className="qr-details">
            <summary>Резервная ссылка для мобильной сети</summary>
            <p>Добавьте эту ссылку как отдельную подписку в приложении и проверьте обновление с выключенным VPN.</p>
            <p>Тестовый адрес работает до {new Date(reserve.expires_at).toLocaleString("ru-RU", { timeZone: "Europe/Moscow" })} МСК.</p>
            <button type="button" className="button ghost" onClick={copyReserve}>Скопировать резервную ссылку</button>
            <p role="status" aria-live="polite">{reserveCopyStatus}</p>
            <input className="connection-uri" aria-label="Резервная ссылка подписки" readOnly value={reserve.url} onFocus={event => event.target.select()} />
          </details>}

          <details className="qr-details">
            <summary>
              Показать QR подписки
            </summary>

            <div className="qr-box">
              <QRCodeSVG
                value={
                  subscription.url
                }
                size={220}
                level="M"
                includeMargin
              />
            </div>
          </details>
        </div>
      )}

      <details className="qr-details">
        <summary>
          Ссылки, QR-коды и VPN-профили
        </summary>

        <ClientConnection
          key={connectionRevision}
          clientID={clientID}
        />
      </details>
    </div>
  );
}

