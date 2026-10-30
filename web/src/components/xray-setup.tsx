"use client";

import {
  useActionState,
} from "react";

import {
  initializeXrayAction,
  type XraySetupState,
} from "@/app/xray-setup-actions";

const initialState: XraySetupState = {
  ok: false,
  message: "",
};

export function InitializeXray({
  node,
  registered,
}: {
  node: string;
  registered: boolean;
}) {
  const [
    state,
    action,
    pending,
  ] = useActionState(
    initializeXrayAction,
    initialState
  );

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2>
            Инициализация Xray
          </h2>

          <p>
            Создайте базовое поколение
            конфигурации перед добавлением
            VPN-сервисов.
          </p>
        </div>
      </div>

      <form action={action}>
        <input
          type="hidden"
          name="node"
          value={node}
        />

        <button
          type="submit"
          disabled={
            !registered ||
            pending
          }
        >
          {pending
            ? "Инициализация…"
            : "Инициализировать Xray"}
        </button>
      </form>

      {!registered && (
        <p className="plan-muted">
          Сначала зарегистрируйте
          Node Agent.
        </p>
      )}

      {state.message && (
        <p
          className={
            state.ok
              ? "operations-good"
              : "operations-warning"
          }
        >
          {state.message}
        </p>
      )}
    </section>
  );
}
