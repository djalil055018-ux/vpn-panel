"use server";

import {
  revalidatePath,
} from "next/cache";
import { randomUUID } from "node:crypto";

import {
  ControlPlaneError,
  configureVPNServiceReality,
  createVPNService,
  disableVPNService,
  enableVPNService,
  updateVPNServiceReality,
  getTLSCertificates,
  getProtocolTemplateTargets,
  previewProtocolTemplate,
  applyProtocolTemplate,
} from "@/lib/control-plane";
import { localRealityTarget, ownCoverDomain } from "@/lib/node-cover";
import { nodeCoverReady } from "@/lib/node-cover-probe";

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
  const session = await requireSession();

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

  if (field(formData, "reality_mode") === "own") {
    if (session.role !== "owner" || !nodeID || !name || port === null || publicPort !== port) {
      return { ok: false, message: "Выберите имя и одинаковые порты. Настройка доступна владельцу." };
    }
    try {
      const cert = (await getTLSCertificates(nodeID))
        .find(item => item.id === field(formData, "cover_certificate") && ownCoverDomain(item.domain));
      if (!cert) return { ok: false, message: "Выпустите действующий сертификат для домена этой ноды." };
      if (!await nodeCoverReady(nodeID, cert.domain)) {
        return { ok: false, message: "HTTPS-страница не прошла проверку. Выполните команду подготовки на ноде и повторите." };
      }
      const template = "vless-reality-vision";
      const { targets, revision } = await getProtocolTemplateTargets(template);
      const target = targets.find(item => item.node_id === nodeID);
      if (!target?.ready) {
        return { ok: false, message: "Для Vision нужна готовая нода с Xray 26.10.21 или новее. Проверьте статус и обновления ядра." };
      }
      const input = { node_id: nodeID, name, port, public_address: cert.domain, certificate_id: "",
        reality_target: localRealityTarget, server_name: cert.domain, plan_ids: [], request_key: randomUUID(),
        expected_generation: target.desired_generation, revision };
      const preview = await previewProtocolTemplate(template, input);
      if (!preview.ready) return { ok: false, message: "Порт занят или состояние ноды изменилось. Обновите страницу и проверьте порт." };
      const result = await applyProtocolTemplate(template, input);
      revalidatePath(`/nodes/${nodeID}/control`);
      return { ok: true, generation: result.generation, message: "VLESS REALITY Vision отправлен на ноду с доменом " + cert.domain + "." };
    } catch (error) {
      return { ok: false, message: errorMessage(error) };
    }
  }

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
