"use server";

import {
  revalidatePath,
} from "next/cache";

import {
  ControlPlaneError,
  configureVPNServiceReality,
  createVPNService,
  disableVPNService,
  enableVPNService,
  updateVPNServiceReality,
} from "@/lib/control-plane";

import {
  requireSession,
} from "@/lib/auth";

export type ProtocolActionState = {
  ok: boolean;
  message: string;
  generation?: number;
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

function validPort(
  value: string
) {
  const port =
    Number.parseInt(
      value,
      10
    );

  if (
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535
  ) {
    return null;
  }

  return port;
}

export async function createVLESSRealityServiceAction(
  _previous: ProtocolActionState,
  formData: FormData
): Promise<ProtocolActionState> {
  await requireSession();

  const nodeID =
    field(
      formData,
      "node_id"
    );

  const name =
    field(
      formData,
      "name"
    );

  const port =
    validPort(
      field(
        formData,
        "port"
      )
    );

  const publicAddress =
    field(
      formData,
      "public_address"
    );

  const publicPort =
    validPort(
      field(
        formData,
        "public_port"
      )
    );

  const destination =
    field(
      formData,
      "destination"
    );

  const serverName =
    field(
      formData,
      "server_name"
    );

  const fingerprint =
    field(
      formData,
      "fingerprint"
    ) || "chrome";

  if (
    !nodeID ||
    !name ||
    port === null ||
    !publicAddress ||
    publicPort === null ||
    !destination ||
    !serverName
  ) {
    return {
      ok: false,
      message:
        "Заполните все обязательные параметры протокола.",
    };
  }

  try {
    const service =
      await createVPNService(
        nodeID,
        {
          name,
          protocol:
            "vless",
          listen:
            "0.0.0.0",
          port,
          transport:
            "tcp",
          security:
            "reality",
          public_address:
            publicAddress,
          public_port:
            publicPort,
        }
      );

    try {
      await configureVPNServiceReality(
        service.id,
        {
          destination,
          server_name:
            serverName,
          fingerprint,
        }
      );
    } catch (error) {
      return {
        ok: false,
        message:
          `Сервис создан отключённым, но REALITY не настроен: ${errorMessage(error)}`,
      };
    }

    try {
      const result =
        await enableVPNService(
          service.id
        );

      revalidatePath(
        `/nodes/${nodeID}/control`
      );

      return {
        ok: true,
        generation:
          result.generation,
        message:
          `VLESS REALITY создан и отправлен на ноду. Поколение ${result.generation}.`,
      };
    } catch (error) {
      return {
        ok: false,
        message:
          `Сервис и REALITY созданы, но включение не завершено: ${errorMessage(error)}`,
      };
    }
  } catch (error) {
    return {
      ok: false,
      message:
        errorMessage(error),
    };
  }
}

export async function updateRealityServiceAction(
  _previous: ProtocolActionState,
  formData: FormData
): Promise<ProtocolActionState> {
  await requireSession();

  const nodeID =
    field(
      formData,
      "node_id"
    );

  const serviceID =
    field(
      formData,
      "service_id"
    );

  const destination =
    field(
      formData,
      "destination"
    );

  const serverName =
    field(
      formData,
      "server_name"
    );

  const fingerprint =
    field(
      formData,
      "fingerprint"
    ) || "chrome";

  const enabled =
    field(
      formData,
      "enabled"
    ) === "true";

  if (
    !nodeID ||
    !serviceID ||
    !destination ||
    !serverName
  ) {
    return {
      ok: false,
      message:
        "Не заполнены обязательные параметры REALITY.",
    };
  }

  try {
    if (enabled) {
      const result =
        await updateVPNServiceReality(
          serviceID,
          {
            destination,
            server_name:
              serverName,
            fingerprint,
          }
        );

      revalidatePath(
        `/nodes/${nodeID}/control`
      );

      return {
        ok: true,
        generation:
          result.generation,
        message:
          `REALITY обновлён. Поколение ${result.generation} отправлено на ноду.`,
      };
    }

    await configureVPNServiceReality(
      serviceID,
      {
        destination,
        server_name:
          serverName,
        fingerprint,
      }
    );

    revalidatePath(
      `/nodes/${nodeID}/control`
    );

    return {
      ok: true,
      message:
        "REALITY-параметры сохранены. Сервис остаётся отключённым.",
    };
  } catch (error) {
    return {
      ok: false,
      message:
        errorMessage(error),
    };
  }
}

export async function toggleVPNServiceAction(
  _previous: ProtocolActionState,
  formData: FormData
): Promise<ProtocolActionState> {
  await requireSession();

  const nodeID =
    field(
      formData,
      "node_id"
    );

  const serviceID =
    field(
      formData,
      "service_id"
    );

  const operation =
    field(
      formData,
      "operation"
    );

  if (
    !nodeID ||
    !serviceID ||
    ![
      "enable",
      "disable",
    ].includes(operation)
  ) {
    return {
      ok: false,
      message:
        "Некорректная операция.",
    };
  }

  try {
    const result =
      operation ===
      "enable"
        ? await enableVPNService(
            serviceID
          )
        : await disableVPNService(
            serviceID
          );

    revalidatePath(
      `/nodes/${nodeID}/control`
    );

    return {
      ok: true,
      generation:
        result.generation,
      message:
        operation ===
        "enable"
          ? `Сервис включён. Поколение ${result.generation}.`
          : `Сервис отключён. Поколение ${result.generation}.`,
    };
  } catch (error) {
    return {
      ok: false,
      message:
        errorMessage(error),
    };
  }
}
