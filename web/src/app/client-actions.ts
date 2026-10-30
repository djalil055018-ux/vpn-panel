"use server";

import { Buffer } from "node:buffer";
import { connectionArchive } from "@/lib/connection-archive";
import {
  connectionCredential,
  connectionMetadata,
  type ConnectionArchiveActionResult,
  type ConnectionCredentialActionResult,
  type ConnectionListActionResult,
} from "@/lib/connection-delivery";


import {
  revalidatePath,
} from "next/cache";

import {
  ControlPlaneError,
  ControlPlaneTimeoutError,
  createVPNClient,
  createVPNClientSubscription,
  getVPNClientConnections,
  getVPNClientSubscription,
  provisionVPNClient,
  rotateVPNClientSubscription,
  type VPNClientSubscription,
  detachVPNClientService,
  getAccessPlan,
  mutateAccessPlan,
} from "@/lib/control-plane";

import {
  requireSession,
} from "@/lib/auth";

export type ClientActionState = {
  ok: boolean;
  message: string;
};

function field(
  formData: FormData,
  name: string
) {
  return String(
    formData.get(name) ?? ""
  ).trim();
}

function errorMessage(
  error: unknown
) {
  if (
    error instanceof
    ControlPlaneError
  ) {
    return `Контур управления: HTTP ${error.status} — ${error.message}`;
  }

  if (
    error instanceof Error
  ) {
    return error.message;
  }

  return "Произошла неизвестная ошибка.";
}

export async function createVPNClientAction(
  _previous: ClientActionState,
  formData: FormData
): Promise<ClientActionState> {
  await requireSession();

  const tenantID =
    field(
      formData,
      "tenant_id"
    );

  const name =
    field(
      formData,
      "name"
    );

  const expiresDate =
    field(
      formData,
      "expires_date"
    );

    const accessPlanID =
      field(
        formData,
        "access_plan_id"
      );


  if (!tenantID) {
    return {
      ok: false,
      message:
        "Выберите владельца клиента.",
    };
  }

  if (!name) {
    return {
      ok: false,
      message:
        "Введите имя клиента.",
    };
  }

  if (name.length > 100) {
    return {
      ok: false,
      message:
        "Имя клиента слишком длинное.",
    };
  }

  let expiresAt:
    string |
    undefined;

  if (expiresDate) {
    if (
      !/^\d{4}-\d{2}-\d{2}$/.test(
        expiresDate
      )
    ) {
      return {
        ok: false,
        message:
          "Некорректная дата окончания.",
      };
    }

    expiresAt =
      `${expiresDate}T23:59:59+03:00`;
  }

  try {
    const selectedPlan =
      accessPlanID
        ? await getAccessPlan(
            accessPlanID
          )
        : null;

    if (
      selectedPlan &&
      (
        selectedPlan.tenant_id !==
          tenantID ||
        !selectedPlan.enabled
      )
    ) {
      return {
        ok: false,
        message:
          "Выбранная группа доступа недоступна для этого владельца.",
      };
    }

    const client =
      await createVPNClient(
        tenantID,
        name,
        expiresAt
      );

    let groupMessage = "";

    if (selectedPlan) {
      try {
        const mutation =
          await mutateAccessPlan(
            selectedPlan.id,
            "POST",
            `/clients/${encodeURIComponent(
              client.id
            )}`
          );

        const nodeMessage =
          mutation.rebuilds.length
            ? ` Обновления отправлены на ноды: ${mutation.rebuilds.length}.`
            : "";

        groupMessage =
          ` Группа доступа «${selectedPlan.name}» назначена.${nodeMessage}`;

        revalidatePath(
          "/access-plans"
        );

        revalidatePath(
          "/nodes"
        );

        revalidatePath(
          "/deployments"
        );
      } catch (error) {
        revalidatePath(
          "/clients"
        );

        return {
          ok: false,
          message:
            `Клиент «${client.name}» создан, но группа доступа «${selectedPlan.name}» не назначена. ` +
            errorMessage(error) +
            " Не создавайте клиента повторно: назначьте группу вручную в разделе «Группы доступа».",
        };
      }
    }


    revalidatePath(
      "/clients"
    );

    return {
      ok: true,
      message:
        `Клиент «${client.name}» создан.${groupMessage}`,
    };
  } catch (error) {
    return {
      ok: false,
      message:
        errorMessage(error),
    };
  }
}

export async function provisionVPNClientAction(
  _previous: ClientActionState,
  formData: FormData
): Promise<ClientActionState> {
  await requireSession();

  const clientID =
    field(
      formData,
      "client_id"
    );

  const serviceID =
    field(
      formData,
      "service_id"
    );

  if (
    !clientID ||
    !serviceID
  ) {
    return {
      ok: false,
      message:
        "Выберите VPN-сервис.",
    };
  }

  try {
    const result =
      await provisionVPNClient(
        serviceID,
        clientID
      );

    revalidatePath(
      "/clients"
    );

    return {
      ok: true,
      message:
        `Подключение принято. Поколение ${result.generation}.`,
    };
  } catch (error) {
    return {
      ok: false,
      message:
        errorMessage(error),
    };
  }
}


export async function detachVPNClientServiceAction(
  _previous: ClientActionState,
  formData: FormData
): Promise<ClientActionState> {
  await requireSession();

  const clientID =
    field(
      formData,
      "client_id"
    );

  const serviceID =
    field(
      formData,
      "service_id"
    );

  if (
    !clientID ||
    !serviceID
  ) {
    return {
      ok: false,
      message:
        "Не удалось определить VPN-сервис.",
    };
  }

  try {
    await detachVPNClientService(
      serviceID,
      clientID
    );

    revalidatePath(
      "/clients"
    );

    return {
      ok: true,
      message:
        "Прямое подключение удалено. Доступ через тарифы, если он назначен, сохраняется.",
    };
  } catch (error) {
    return {
      ok: false,
      message:
        errorMessage(error),
    };
  }
}


const connectionIDPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function getVPNClientConnectionsAction(
  clientID: string
): Promise<ConnectionListActionResult> {
  await requireSession();

  const id =
    String(clientID ?? "").trim();

  if (!connectionIDPattern.test(id)) {
    return {
      ok: false,
      message: "Некорректный клиент.",
      connections: [],
    };
  }

  try {
    /*
     * CP returns the full connection object to the trusted Web server.
     * Only non-secret metadata is serialized back to the browser.
     */
    const connections =
      await getVPNClientConnections(id);

    return {
      ok: connections.length > 0,
      message:
        connections.length > 0
          ? `Доступно подключений: ${connections.length}.`
          : "Для клиента пока нет готового подключения.",
      connections:
        connections.map(
          connectionMetadata
        ),
    };
  } catch (error) {
    return {
      ok: false,
      message: errorMessage(error),
      connections: [],
    };
  }
}

export async function getVPNClientCredentialAction(
  clientID: string,
  serviceID: string
): Promise<ConnectionCredentialActionResult> {
  await requireSession();

  const client =
    String(clientID ?? "").trim();

  const service =
    String(serviceID ?? "").trim();

  if (
    !connectionIDPattern.test(client) ||
    !connectionIDPattern.test(service)
  ) {
    return {
      ok: false,
      message: "Некорректное подключение.",
    };
  }

  try {
    /*
     * Fresh effective-access check immediately before disclosure.
     * A stale browser card is insufficient to obtain a credential.
     */
    const connections =
      await getVPNClientConnections(client);

    const current =
      connections.find(
        (connection) =>
          connection.service_id === service
      );

    const credential =
      current
        ? connectionCredential(current)
        : undefined;

    if (!credential) {
      return {
        ok: false,
        message:
          "Подключение больше недоступно или профиль ещё не готов.",
      };
    }

    return {
      ok: true,
      message: "Профиль проверен.",
      credential,
    };
  } catch (error) {
    return {
      ok: false,
      message: errorMessage(error),
      retryable: error instanceof ControlPlaneTimeoutError,
    };
  }
}

export async function getVPNClientArchiveAction(
  clientID: string
): Promise<ConnectionArchiveActionResult> {
  await requireSession();

  const id =
    String(clientID ?? "").trim();

  if (!connectionIDPattern.test(id)) {
    return {
      ok: false,
      message: "Некорректный клиент.",
    };
  }

  try {
    /*
     * The archive is created only after an explicit user action and a
     * fresh effective-access fetch. Raw individual connections are not
     * returned by the normal list action.
     */
    const connections =
      await getVPNClientConnections(id);

    if (!connections.length) {
      return {
        ok: false,
        message:
          "Нет доступных профилей для архива.",
      };
    }

    const archive =
      connectionArchive(connections);

    return {
      ok: true,
      message: "Архив готов.",
      archive_base64:
        Buffer.from(archive).toString(
          "base64"
        ),
      filename: "vpn-profiles.zip",
      mime: "application/zip",
    };
  } catch (error) {
    return {
      ok: false,
      message: errorMessage(error),
      retryable: error instanceof ControlPlaneTimeoutError,
    };
  }
}


export type SubscriptionActionResult = {

  ok: boolean;
  exists: boolean;
  message: string;
  subscription:
    | (VPNClientSubscription & {
        url: string;
      })
    | null;
};

function subscriptionResult(
  subscription:
    VPNClientSubscription
): SubscriptionActionResult {
  const base =
    String(
      process.env
        .VPN_PLATFORM_PUBLIC_URL ??
        ""
    ).trim();

  if (!base) {
    throw new Error(
      "Не настроен публичный адрес VPN-платформы."
    );
  }

  if (
    !subscription.path.startsWith(
      "/sub/"
    )
  ) {
    throw new Error(
      "Контур управления вернул некорректный путь подписки."
    );
  }

  const url =
    new URL(
      subscription.path,
      base.endsWith("/")
        ? base
        : `${base}/`
    ).toString();

  return {
    ok: true,
    exists: true,
    message:
      "VPN-подписка готова.",
    subscription: {
      ...subscription,
      url,
    },
  };
}

export async function getVPNClientSubscriptionAction(
  clientID: string
): Promise<SubscriptionActionResult> {
  await requireSession();

  const id =
    String(
      clientID ?? ""
    ).trim();

  if (!id) {
    return {
      ok: false,
      exists: false,
      message:
        "Не указан клиент.",
      subscription: null,
    };
  }

  try {
    const subscription =
      await getVPNClientSubscription(
        id
      );

    return subscriptionResult(
      subscription
    );
  } catch (error) {
    if (
      error instanceof
        ControlPlaneError &&
      error.status === 404
    ) {
      return {
        ok: true,
        exists: false,
        message:
          "VPN-подписка ещё не создана.",
        subscription: null,
      };
    }

    return {
      ok: false,
      exists: false,
      message:
        errorMessage(error),
      subscription: null,
    };
  }
}

export async function createVPNClientSubscriptionAction(
  clientID: string
): Promise<SubscriptionActionResult> {
  await requireSession();

  const id =
    String(
      clientID ?? ""
    ).trim();

  if (!id) {
    return {
      ok: false,
      exists: false,
      message:
        "Не указан клиент.",
      subscription: null,
    };
  }

  try {
    const subscription =
      await createVPNClientSubscription(
        id
      );

    revalidatePath(
      "/clients"
    );

    return subscriptionResult(
      subscription
    );
  } catch (error) {
    return {
      ok: false,
      exists: false,
      message:
        errorMessage(error),
      subscription: null,
    };
  }
}

export async function rotateVPNClientSubscriptionAction(
  clientID: string
): Promise<SubscriptionActionResult> {
  await requireSession();

  const id =
    String(
      clientID ?? ""
    ).trim();

  if (!id) {
    return {
      ok: false,
      exists: false,
      message:
        "Не указан клиент.",
      subscription: null,
    };
  }

  try {
    const subscription =
      await rotateVPNClientSubscription(
        id
      );

    revalidatePath(
      "/clients"
    );

    return {
      ...subscriptionResult(
        subscription
      ),
      message:
        "Ссылка VPN-подписки перевыпущена. Старая ссылка больше не работает.",
    };
  } catch (error) {
    return {
      ok: false,
      exists: false,
      message:
        errorMessage(error),
      subscription: null,
    };
  }
}
