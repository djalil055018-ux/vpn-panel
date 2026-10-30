"use server";

import {
  revalidatePath,
} from "next/cache";

import {
  ControlPlaneError,
  initializeXray,
} from "@/lib/control-plane";

import {
  requireSession,
} from "@/lib/auth";

export type XraySetupState = {
  ok: boolean;
  message: string;
  generation?: number;
};

function errorMessage(
  error: unknown
) {
  if (
    error instanceof
    ControlPlaneError
  ) {
    return (
      `Контур управления: HTTP ` +
      `${error.status} — ${error.message}`
    );
  }

  if (
    error instanceof Error
  ) {
    return error.message;
  }

  return "Неизвестная ошибка.";
}

export async function initializeXrayAction(
  _previous: XraySetupState,
  formData: FormData
): Promise<XraySetupState> {
  await requireSession();

  const node =
    String(
      formData.get("node") ?? ""
    ).trim();

  if (!node) {
    return {
      ok: false,
      message:
        "Не указан идентификатор ноды.",
    };
  }

  try {
    const result =
      await initializeXray(node);

    revalidatePath(
      `/nodes/${node}/control`
    );

    return {
      ok: true,
      generation:
        result.generation,
      message:
        result.changed
          ? (
              `Xray инициализирован. ` +
              `Поколение ${result.generation}, ` +
              `ядро ${result.version}.`
            )
          : (
              `Xray уже инициализирован. ` +
              `Текущее поколение ` +
              `${result.generation}.`
            ),
    };
  } catch (error) {
    return {
      ok: false,
      message:
        errorMessage(error),
    };
  }
}
