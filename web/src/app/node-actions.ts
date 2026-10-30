"use server";
import { type NodeRuntime } from "@/lib/node-runtime";
import { nodeOnboardingProgress } from "@/lib/node-onboarding";

import {
  revalidatePath,
} from "next/cache";

import {
  ControlPlaneError,
  createNode,
  getNode,
  renameNode,
} from "@/lib/control-plane";

import {
  requireSession,
} from "@/lib/auth";

export type CreateNodeActionState = {
  ok: boolean;
  title: string;
  message: string;

  node?: {
    id: string;
    name: string;
    runtimeCore: NodeRuntime;
  };

  bootstrapToken?: string;
};

function field(
  formData: FormData,
  name: string
) {
  return String(
    formData.get(name) ?? ""
  ).trim();
}

export async function createNodeAction(
  _previous:
    CreateNodeActionState,
  formData: FormData
): Promise<CreateNodeActionState> {
  await requireSession();

  const runtime = field(formData, "runtime_core") || "xray";
  if (runtime !== "xray" && runtime !== "hysteria2" && runtime !== "openvpn" && runtime !== "wireguard" && runtime !== "pptp" && runtime !== "amneziawg") {
    return { ok: false, title: "Не выбрано ядро", message: "Выберите тип ноды из списка." };
  }

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

  if (!tenantID) {
    return {
      ok: false,
      title: "Не выбран владелец",
      message:
        "Выберите владельца новой ноды.",
    };
  }

  if (!name) {
    return {
      ok: false,
      title: "Не указано имя",
      message:
        "Введите имя новой ноды.",
    };
  }

  if (name.length > 80) {
    return {
      ok: false,
      title: "Слишком длинное имя",
      message:
        "Имя должно содержать не более 80 символов.",
    };
  }

  try {
    const result =
      await createNode(
        tenantID,
        name,
        runtime
      );

    revalidatePath("/nodes");
    revalidatePath("/dashboard");

    return {
      ok: true,
      title: "Нода создана",
      message:
        "Сохраните токен первичной регистрации до завершения подключения ноды.",
      node: {
        id: result.node.id,
        name: result.node.name,
        runtimeCore: result.node.runtime_core ?? "xray",
      },
      bootstrapToken:
        result.bootstrap_token,
    };
  } catch (error) {
    if (
      error instanceof
      ControlPlaneError
    ) {
      return {
        ok: false,
        title:
          "Контур управления отклонил запрос",
        message:
          `HTTP ${error.status}: ${error.message}`,
      };
    }

    if (
      error instanceof Error
    ) {
      return {
        ok: false,
        title:
          "Ошибка создания ноды",
        message:
          error.message,
      };
    }

    return {
      ok: false,
      title:
        "Ошибка создания ноды",
      message:
        "Произошла неизвестная ошибка.",
    };
  }
}


export type NodeOnboardingStatus = {
  ok: boolean;
  message: string;
  ready?: boolean;
  label?: string;
  registered?: boolean;
  bootstrapConsumed?: boolean;
  online?: boolean;
  state?: string;
  agentVersion?: string;
  osName?: string;
  osVersion?: string;
  architecture?: string;
  lastSeenAt?: string;
};

export async function getNodeOnboardingStatusAction(
  nodeID: string
): Promise<NodeOnboardingStatus> {
  await requireSession();

  const id =
    String(nodeID ?? "").trim();

  if (!id) {
    return {
      ok: false,
      message:
        "Не указан идентификатор ноды.",
    };
  }

  try {
    const detail =
      await getNode(id);

    const lifecycle =
      detail.lifecycle;
    const progress = nodeOnboardingProgress(lifecycle);

    return {
      ok: true,
      ...progress,
      registered:
        lifecycle.registered,
      bootstrapConsumed:
        lifecycle.bootstrap_consumed,
      online:
        lifecycle.online,
      state:
        lifecycle.state,
      agentVersion:
        lifecycle.agent_version,
      osName:
        lifecycle.os_name,
      osVersion:
        lifecycle.os_version,
      architecture:
        lifecycle.architecture,
      lastSeenAt:
        lifecycle.last_seen_at,
    };
  } catch (error) {
    if (
      error instanceof
      ControlPlaneError
    ) {
      return {
        ok: false,
        message:
          `Контур управления вернул HTTP ${error.status}.`,
      };
    }

    return {
      ok: false,
      message:
        "Не удалось получить состояние ноды.",
    };
  }
}

export type RenameNodeActionState = {
  ok: boolean;
  message: string;
};

export async function renameNodeAction(
  _previous: RenameNodeActionState,
  formData: FormData
): Promise<RenameNodeActionState> {
  const session = await requireSession();
  if (session.role !== "owner") {
    return { ok: false, message: "Переименовывать серверы может только владелец панели." };
  }
  const id = String(formData.get("node_id") ?? "").trim();
  const name = String(formData.get("name") ?? "").trim();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    return { ok: false, message: "Не удалось определить сервер. Обновите страницу и повторите." };
  }
  if (!name || Array.from(name).length > 80 || /[\u0000-\u001f\u007f-\u009f]/u.test(name)) {
    return { ok: false, message: "Введите название длиной до 80 символов без управляющих символов." };
  }
  try {
    const result = await renameNode(id, name);
    if (result.node_id !== id || result.name !== name) {
      return { ok: false, message: "Панель вернула неожиданный результат. Проверьте список серверов." };
    }
    for (const path of ["/nodes", "/dashboard", "/clients", "/access-plans", "/operations", `/nodes/${id}`]) {
      revalidatePath(path);
    }
    return { ok: true, message: result.changed ? "Название сервера изменено." : "Название не изменилось." };
  } catch (error) {
    if (error instanceof ControlPlaneError) {
      if (error.status === 409) return { ok: false, message: "Сервер с таким названием уже есть или запись находится в архиве." };
      if (error.status === 400) return { ok: false, message: "Проверьте название: до 80 символов." };
      if (error.status === 403) return { ok: false, message: "Недостаточно прав для переименования сервера." };
    }
    return { ok: false, message: "Не удалось изменить название сервера. Повторите попытку." };
  }
}
