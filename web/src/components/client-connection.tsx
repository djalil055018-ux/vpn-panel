"use client";

import {
  useState,
  useTransition,
} from "react";

import { unstable_rethrow } from "next/navigation";
import { rotatePPTPCredentialAction } from "@/app/pptp-actions";

import {
  QRCodeSVG,
} from "qrcode.react";

import {
  getVPNClientArchiveAction,
  getVPNClientConnectionsAction,
  getVPNClientCredentialAction,
} from "@/app/client-actions";

import {
  portalConnectionCredentialAction,
  portalConnectionsAction,
  portalConnectionsArchiveAction,
} from "@/app/portal/actions";

import type {
  ConnectionCredential,
  ConnectionMetadata,
} from "@/lib/connection-delivery";

import {
  connectionImportHint,
  connectionLabel,
} from "@/lib/connection-labels";

type RevealedValue = {
  serviceID: string;
  value: string;
};

export function ClientConnection({
  clientID,
  audience = "admin",
}: {
  clientID: string;
  audience?: "admin" | "portal";
}) {
  const listConnections =
    audience === "portal"
      ? portalConnectionsAction
      : getVPNClientConnectionsAction;

  const fetchCredential =
    audience === "portal"
      ? portalConnectionCredentialAction
      : getVPNClientCredentialAction;

  const fetchArchive =
    audience === "portal"
      ? portalConnectionsArchiveAction
      : getVPNClientArchiveAction;

  const [
    pending,
    startTransition,
  ] =
    useTransition();

  /*
   * This state is metadata-only. It never contains uri/config/password,
   * UUIDs, private keys or other connection credentials.
   */
  const [
    connections,
    setConnections,
  ] =
    useState<
      ConnectionMetadata[]
    >([]);

  const [
    message,
    setMessage,
  ] =
    useState("");

  const [
    copied,
    setCopied,
  ] =
    useState("");

  const [
    revealed,
    setRevealed,
  ] =
    useState<
      RevealedValue | null
    >(null);

  const [
    qr,
    setQR,
  ] =
    useState<
      RevealedValue | null
    >(null);

  function clearDisplayedCredentials() {
    setRevealed(null);
    setQR(null);
    setCopied("");
  }

  async function refreshMetadata() {
    clearDisplayedCredentials();

    try {
      const result =
        await listConnections(
          clientID
        );

      setConnections(
        result.connections
      );

      setMessage(
        result.message
      );

      return result.connections;
    } catch (error) {
      unstable_rethrow(error);
      setConnections([]);

      setMessage(
        "Не удалось проверить доступ. Обновите подключения и повторите попытку."
      );

      return [];
    }
  }

  function runDelivery(action: () => Promise<void>) {
    clearDisplayedCredentials();
    setMessage("");

    startTransition(async () => {
      try {
        await action();
      } catch (error) {
        // Preserve framework redirects, including an expired admin session.
        unstable_rethrow(error);
        clearDisplayedCredentials();
        setConnections([]);
        setMessage(
          "Не удалось получить данные доступа. Проверьте соединение и обновите подключения."
        );
      }
    });
  }

  function save(
    data: BlobPart,
    type: string,
    filename: string
  ) {
    const url =
      URL.createObjectURL(
        new Blob(
          [data],
          { type }
        )
      );

    const link =
      document.createElement("a");

    link.href = url;
    link.download = filename;
    link.click();

    window.setTimeout(
      () =>
        URL.revokeObjectURL(
          url
        ),
      1000
    );
  }

  function saveBase64(
    value: string,
    type: string,
    filename: string
  ) {
    const binary =
      window.atob(value);

    const bytes =
      new Uint8Array(
        binary.length
      );

    for (
      let index = 0;
      index < binary.length;
      index += 1
    ) {
      bytes[index] =
        binary.charCodeAt(
          index
        );
    }

    save(
      bytes,
      type,
      filename
    );
  }

  function exportOne(
    serviceID: string,
    kind:
      | "download"
      | "copy"
      | "qr"
      | "show"
  ) {
    runDelivery(
      async () => {
        /*
         * Credential disclosure is a separate server action.
         * The server performs a fresh effective-access fetch before
         * returning exactly one requested credential.
         */
        const result =
          await fetchCredential(
            clientID,
            serviceID
          );

        if (
          !result.ok ||
          !result.credential
        ) {
          clearDisplayedCredentials();

          setMessage(
            result.message
          );

          if (result.retryable) {
            // A timed-out CP read must not trigger another automatic read.
            setConnections([]);
            return;
          }

          /*
           * Refresh metadata after denial so a stale revoked card
           * disappears from the browser.
           */
          await refreshMetadata();
          return;
        }

        const credential:
          ConnectionCredential =
            result.credential;

        const value =
          credential.value;

        setMessage(
          result.message
        );

        if (
          kind === "show"
        ) {
          setRevealed({
            serviceID,
            value,
          });
          setQR(null);
          return;
        }

        if (
          kind === "qr"
        ) {
          setQR({
            serviceID,
            value,
          });
          setRevealed(null);
          return;
        }

        if (
          kind ===
          "download"
        ) {
          if (
            credential.kind !==
              "config" ||
            !credential.filename
          ) {
            setMessage(
              "Для этого подключения нет отдельного файла."
            );
            return;
          }

          save(
            value,
            "text/plain;charset=utf-8",
            credential.filename
          );
          return;
        }

        try {
          await navigator
            .clipboard
            .writeText(value);

          setCopied(
            serviceID
          );

          window.setTimeout(
            () =>
              setCopied(""),
            1800
          );
        } catch {
          setMessage(
            "Не удалось скопировать автоматически. Нажмите «Показать профиль» для ручного копирования."
          );
        }
      }
    );
  }

  function downloadAll() {
    runDelivery(
      async () => {
        const result =
          await fetchArchive(
            clientID
          );

        setMessage(
          result.message
        );

        if (
          !result.ok ||
          !result.archive_base64 ||
          !result.filename ||
          !result.mime
        ) {
          if (result.retryable) {
            setConnections([]);
            return;
          }
          await refreshMetadata();
          return;
        }

        saveBase64(
          result.archive_base64,
          result.mime,
          result.filename
        );

        /*
         * Refresh cards after archive generation because effective
         * access may have changed since the previous metadata listing.
         */
        await refreshMetadata();
      }
    );
  }

  return (
    <div className="connection-control">
      <button
        type="button"
        className="button ghost"
        onClick={() =>
          startTransition(
            async () => {
              await refreshMetadata();
            }
          )
        }
        disabled={pending}
      >
        {pending
          ? "Проверяем доступ…"
          : connections.length
            ? "Обновить подключения"
            : "Получить подключения"}
      </button>

      {connections.length >
        0 && (
        <button
          type="button"
          className="button ghost"
          onClick={
            downloadAll
          }
          disabled={pending}
        >
          Скачать все профили .zip
        </button>
      )}

      {message && (
        <small
          role="status"
          className="client-action-message"
        >
          {message}
        </small>
      )}

      {connections.map(
        (connection) => {
          const hasCredential =
            connection.has_config ||
            connection.has_uri;

          const isRevealed =
            revealed?.serviceID ===
            connection.service_id;

          const qrVisible =
            qr?.serviceID ===
            connection.service_id;

          return (
            <div
              key={
                connection.service_id
              }
              className="connection-card"
            >
              <div className="connection-card-head">
                <div>
                  <strong>
                    {
                      connection.service_name
                    }
                  </strong>

                  <span>
                    {connection.address.includes(
                      ":"
                    )
                      ? `[${connection.address}]`
                      : connection.address}
                    :
                    {connection.port}
                    {" · "}
                    {connectionLabel(
                      connection
                    )}
                  </span>
                </div>
              </div>

              <p className="muted">
                {connectionImportHint(
                  connection
                )}
              </p>

              <p className="plan-muted">
                Данные доступа не
                загружаются в браузер
                вместе со списком.
                Конкретный профиль
                запрашивается только
                после явного действия
                и повторной проверки
                доступа.
              </p>

              {connection.protocol ===
                "openvpn" &&
                connection.config_expires_at && (
                  <p className="muted">
                    Сертификат профиля
                    действует до{" "}
                    {new Date(
                      connection.config_expires_at
                    ).toLocaleDateString(
                      "ru-RU"
                    )}
                    . Перед этой датой
                    скачайте новый профиль.
                    Отзыв доступа отключает
                    ранее выданный доступ.
                  </p>
                )}

              <div className="connection-buttons">
                {audience === "admin" && connection.protocol === "pptp" && (
                  <button type="button" className="button ghost" disabled={pending}
                    onClick={() => runDelivery(async () => {
                      const result=await rotatePPTPCredentialAction(clientID,connection.service_id);
                      await refreshMetadata();
                      setMessage(result.message);
                    })}>Сменить пароль и отключить старый туннель</button>
                )}
                {connection.has_config && (
                  <button
                    type="button"
                    className="button primary"
                    disabled={pending}
                    onClick={() =>
                      exportOne(
                        connection.service_id,
                        "download"
                      )
                    }
                  >
                    Скачать{" "}
                    {connection.protocol ===
                    "openvpn"
                      ? ".ovpn"
                      : connection.protocol === "pptp" ? "инструкцию .pptp.txt" : ".conf"}
                  </button>
                )}

                {hasCredential && (
                  <button
                    type="button"
                    className="button primary"
                    disabled={pending}
                    onClick={() =>
                      exportOne(
                        connection.service_id,
                        "copy"
                      )
                    }
                  >
                    {copied ===
                    connection.service_id
                      ? "Скопировано"
                      : connection.has_config
                        ? "Скопировать профиль"
                        : "Скопировать ссылку"}
                  </button>
                )}

                {hasCredential && (
                  <button
                    type="button"
                    className="button ghost"
                    disabled={pending}
                    aria-expanded={
                      isRevealed
                    }
                    onClick={() => {
                      if (
                        isRevealed
                      ) {
                        setRevealed(
                          null
                        );
                        return;
                      }

                      exportOne(
                        connection.service_id,
                        "show"
                      );
                    }}
                  >
                    {isRevealed
                      ? "Скрыть профиль"
                      : connection.has_config
                        ? "Показать профиль"
                        : "Показать ссылку"}
                  </button>
                )}

                {connection.protocol !==
                  "openvpn" && connection.protocol !== "pptp" &&
                  hasCredential && (
                    <button
                      type="button"
                      className="button ghost"
                      disabled={pending}
                      aria-expanded={
                        qrVisible
                      }
                      onClick={() => {
                        if (
                          qrVisible
                        ) {
                          setQR(
                            null
                          );
                          return;
                        }

                        exportOne(
                          connection.service_id,
                          "qr"
                        );
                      }}
                    >
                      {qrVisible
                        ? "Скрыть QR-код"
                        : "Показать QR-код"}
                    </button>
                  )}
              </div>

              {isRevealed &&
                revealed && (
                  <code className="connection-uri">
                    {
                      revealed.value
                    }
                  </code>
                )}

              {qrVisible &&
                qr && (
                  <div className="qr-box">
                    <QRCodeSVG
                      value={
                        qr.value
                      }
                      size={220}
                      level="M"
                      includeMargin
                    />
                  </div>
                )}
            </div>
          );
        }
      )}
    </div>
  );
}
