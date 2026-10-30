"use client";

import { useRouter } from "next/navigation";

import { ClientLifecycle } from "@/components/client-lifecycle";
import { ClientDelete } from "@/components/client-delete";

import {
  useActionState,
  useTransition,
  useRef,
  useEffect,
} from "react";

import {
  useFormStatus,
} from "react-dom";

import {
  createVPNClientAction,
  detachVPNClientServiceAction,
  provisionVPNClientAction,
  type ClientActionState,
} from "@/app/client-actions";

import {
  ClientSubscription,
} from "@/components/client-subscription";

import { ClientDataTable } from "@/components/client-data-table";
import { ClientUsage } from "@/components/client-usage";
import { ClientDevices } from "@/components/client-devices";
import type { DeviceCategory } from "@/lib/device-categories";

import type {
  TenantRecord,
  VPNClientRecord,
  VPNClientUsage,
} from "@/lib/control-plane";

export type ClientServiceOption = {
  id: string;
  label: string;
};

const initialState:
  ClientActionState = {
    ok: false,
    message: "",
  };

function SubmitButton({
  children,
}: {
  children: React.ReactNode;
}) {
  const {
    pending,
  } =
    useFormStatus();

  return (
    <button
      type="submit"
      className="button primary"
      disabled={pending}
    >
      {pending
        ? "Выполняется..."
        : children}
    </button>
  );
}

function ProvisionForm({
  clientID,
  services,
}: {
  clientID: string;
  services:
    ClientServiceOption[];
}) {
  const [
    state,
    action,
  ] =
    useActionState(
      provisionVPNClientAction,
      initialState
    );

  return (
    <form
      action={action}
      className="client-provision-form"
    >
      <input
        type="hidden"
        name="client_id"
        value={clientID}
      />

      <select
        name="service_id"
        required
        defaultValue=""
      >
        <option
          value=""
          disabled
        >
          Выберите VPN-сервис
        </option>

        {services.map(
          (service) => (
            <option
              key={service.id}
              value={service.id}
            >
              {service.label}
            </option>
          )
        )}
      </select>

      <SubmitButton>
        Подключить
      </SubmitButton>

      {state.message && (
        <small
          className={
            state.ok
              ? "client-action-message success"
              : "client-action-message error"
          }
        >
          {state.message}
        </small>
      )}
    </form>
  );
}

function DisconnectButton({
  serviceID,
}: {
  serviceID: string;
}) {
  const {
    pending,
  } =
    useFormStatus();

  return (
    <button
      type="submit"
      name="service_id"
      value={serviceID}
      className="button ghost"
      disabled={pending}
    >
      {pending
        ? "Отключение..."
        : "Отключить"}
    </button>
  );
}

function DirectServices({
  clientID,
  services,
}: {
  clientID: string;
  services:
    ClientServiceOption[] | null;
}) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  const [
    state,
    action,
  ] =
    useActionState(
      detachVPNClientServiceAction,
      initialState
    );

  return (
    <div className="client-provision-form">
      <small>
        Подключены напрямую
      </small>

      {services === null && (
        <div role="status">
          <small className="client-action-message error">
            Не удалось загрузить прямые подключения. Их состояние неизвестно.
          </small>
          <button
            type="button"
            className="button ghost"
            disabled={refreshing}
            onClick={() => startRefresh(() => router.refresh())}
          >
            {refreshing ? "Загрузка..." : "Повторить загрузку"}
          </button>
        </div>
      )}

      {services?.length === 0 && (
        <small className="plan-muted">
          Нет прямых подключений.
        </small>
      )}

      {services?.map(
        (service) => (
          <form
            key={service.id}
            action={action}
            className="plan-actions"
          >
            <input
              type="hidden"
              name="client_id"
              value={clientID}
            />

            <span>
              {service.label}
            </span>

            <DisconnectButton
              serviceID={
                service.id
              }
            />
          </form>
        )
      )}

      {state.message && (
        <small
          className={
            state.ok
              ? "client-action-message success"
              : "client-action-message error"
          }
        >
          {state.message}
        </small>
      )}
    </div>
  );
}

type ClientAccessPlanOption = {
  id: string;
  tenant_id: string;
  name: string;
};

export function ClientManagement({
  tenants,
    accessPlans,
  clients,
  usages,
  services,
  directServices,
  connectionRevision,
  canDeleteImported,
  clientCategories,
}: {
  tenants:
    TenantRecord[];
    accessPlans:
      ClientAccessPlanOption[];
  clients:
    VPNClientRecord[];
  usages:
    (VPNClientUsage | null)[];
  services:
    ClientServiceOption[];
  connectionRevision: string;
  canDeleteImported: boolean;
  directServices:
    Record<string, ClientServiceOption[] | null>;
  clientCategories: Record<string, DeviceCategory[]>;
}) {
  const [
    createState,
    createAction,
  ] =
    useActionState(
      createVPNClientAction,
      initialState
    );

  const createDialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { if (createState.ok) createDialog.current?.close(); }, [createState]);

  return (
    <>
      <dialog ref={createDialog} className="client-create-dialog">
        <div className="panel-header">
          <div>
            <h2>
              Новый клиент
            </h2>
            <p>
              Создание пользователя VPN и срока действия.
            </p>
          </div>
          <button type="button" className="button ghost" aria-label="Закрыть создание клиента" onClick={() => createDialog.current?.close()}>✕</button>
        </div>

        <form
          action={createAction}
          className="add-node-form client-create-form"
        >
          <label>
            <span>
              Владелец
            </span>

            <select
              name="tenant_id"
              required
              defaultValue={
                tenants[0]?.id ??
                ""
              }
            >
              {tenants.map(
                (tenant) => (
                  <option
                    key={tenant.id}
                    value={tenant.id}
                  >
                    {tenant.name}
                  </option>
                )
              )}
            </select>
          </label>

          <label>
            <span>
              Имя клиента
            </span>

            <input
              type="text"
              name="name"
              required
              maxLength={100}
              placeholder="Например: Иван"
            />
          </label>

          <label>
            <span>
              Действует до (Москва)
            </span>

            <input
              type="date"
              name="expires_date"
            />

            <small>
              Оставьте пустым для бессрочного клиента.
            </small>
          </label>

          <label>
            <span>
              Группа доступа
            </span>

            <select
              name="access_plan_id"
              defaultValue=""
            >
              <option value="">
                Без группы
              </option>

              {accessPlans.map(
                (plan) => {
                  const tenant =
                    tenants.find(
                      (item) =>
                        item.id ===
                        plan.tenant_id
                    );

                  return (
                    <option
                      key={plan.id}
                      value={plan.id}
                    >
                      {tenant
                        ? `${tenant.name} · ${plan.name}`
                        : plan.name}
                    </option>
                  );
                }
              )}
            </select>

            <small>
              Все сервисы группы будут назначены клиенту автоматически.
            </small>
          </label>

          <div className="client-create-submit">
            <SubmitButton>
              + Добавить клиента
            </SubmitButton>
          </div>

          {createState.message && (
            <div
              className={
                createState.ok
                  ? "client-action-message success"
                  : "client-action-message error"
              }
            >
              {createState.message}
            </div>
          )}
        </form>
      </dialog>
      <ClientDataTable clients={clients} usages={usages} clientCategories={clientCategories} onCreate={() => createDialog.current?.showModal()}
        details={(client, index) => (
          <div className="client-record-content">
              <section className="client-detail-block"><h3>Доступ и срок действия</h3>
                {client.remnawave_hold ? <p className="plan-muted">Перенос ещё не завершён. Данные исходной панели сохранены в снимке.</p> : <ClientLifecycle id={client.id} name={client.name} status={client.status} expiresAt={client.expires_at}/>}
                {(!client.remnawave_hold || canDeleteImported) && <ClientDelete id={client.id} name={client.name} imported={client.remnawave_hold}/>}
              </section>
              <section className="client-detail-block"><h3>VPN-сервисы</h3>
                {client.remnawave_hold ? <p className="plan-muted">Ожидает сопоставления сервисов</p> : <><ProvisionForm clientID={client.id} services={services}/><DirectServices clientID={client.id} services={directServices[client.id] ?? null}/></>}
              </section>
              <section className="client-detail-block"><h3>Подписка и подключение</h3>
                {client.remnawave_hold ? <p className="plan-muted">Исходная подписка сохранена в снимке</p> : <ClientSubscription connectionRevision={connectionRevision} clientID={client.id}/>}
              </section>
              {!client.remnawave_hold && <section className="client-detail-block client-device-section"><h3>Устройства подписки</h3><ClientDevices key={client.id} clientID={client.id}/></section>}
              <section className="client-detail-block"><h3>Трафик и лимиты</h3>
                {client.remnawave_hold ? <p className="plan-muted">Исходный трафик и ограничения сохранены в снимке</p> : <ClientUsage clientID={client.id} usage={usages[index] ?? null}/>}
              </section>
            </div>
        )}/>
    </>
  );
}
