"use server";

import {
  revalidatePath,
} from "next/cache";

import {
  approveRecoveryAttempt,
  approveRolloutPlan,
  cancelRecoveryAttempt,
  cancelRolloutPlan,
  ControlPlaneError,
  createRecoveryAttempt,
  createRolloutPlan,
  evaluateCoreUpdate,
  executeRecoveryAttempt,
  executeRolloutPlan,
  getRecoveryEvaluation,
  getNode,
} from "@/lib/control-plane";

import {
  requireSession,
} from "@/lib/auth";

export type ControlActionState = {
  ok: boolean;
  title: string;
  message: string;
  data?: unknown;
};

function text(
  formData: FormData,
  name: string
) {
  return String(
    formData.get(name) ??
      ""
  ).trim();
}

function errorState(
  title: string,
  error: unknown
): ControlActionState {
  if (
    error instanceof
    ControlPlaneError
  ) {
    return {
      ok: false,
      title,
      message:
        `Control Plane HTTP ${error.status}: ${error.message}`,
    };
  }

  if (
    error instanceof Error
  ) {
    return {
      ok: false,
      title,
      message:
        error.message,
    };
  }

  return {
    ok: false,
    title,
    message:
      "Неизвестная ошибка",
  };
}

export async function evaluateCoreUpdateAction(
  _previous:
    ControlActionState,
  formData:
    FormData
): Promise<ControlActionState> {
  await requireSession();

  const nodeID =
    text(
      formData,
      "node_id"
    );

  const version =
    text(
      formData,
      "version"
    );

  if (
    !nodeID ||
    !version
  ) {
    return {
      ok: false,
      title:
        "Проверка обновления ядра",
      message:
        "Необходимо указать ноду и целевую версию.",
    };
  }

  try {
    const runtime = (await getNode(nodeID)).node.runtime_core ?? "xray";
    const result =
      await evaluateCoreUpdate(
        nodeID,
        version,
        runtime
      );

    return {
      ok: true,
      title:
        "Проверка обновления ядра",
      message:
        `Проверка ${runtime === "hysteria2" ? "Hysteria 2" : "Xray"} ${version} завершена.`,
      data:
        result,
    };
  } catch (error) {
    return errorState(
      "Проверка обновления ядра",
      error
    );
  }
}

export async function createRolloutAction(
  _previous:
    ControlActionState,
  formData:
    FormData
): Promise<ControlActionState> {
  await requireSession();

  const nodeID =
    text(
      formData,
      "node_id"
    );

  if (!nodeID) {
    return {
      ok: false,
      title:
        "Создание плана обновления",
      message:
        "Не указан ID ноды.",
    };
  }

  try {
    const runtime = (await getNode(nodeID)).node.runtime_core ?? "xray";
    const plan =
      await createRolloutPlan(
        nodeID,
        runtime
      );

    return {
      ok: true,
      title:
        "План обновления создан",
      message:
        `План ${plan.id} создан. Развёртывание ещё не запускалось.`,
      data:
        plan,
    };
  } catch (error) {
    return errorState(
      "Создание плана обновления",
      error
    );
  }
}

export async function mutateRolloutAction(
  _previous:
    ControlActionState,
  formData:
    FormData
): Promise<ControlActionState> {
  await requireSession();

  const nodeID =
    text(
      formData,
      "node_id"
    );

  const planID =
    text(
      formData,
      "plan_id"
    );

  const operation =
    text(
      formData,
      "operation"
    );

  if (!planID) {
    return {
      ok: false,
      title:
        "Rollout",
      message:
        "Не указан ID плана обновления.",
    };
  }

  try {
    let result:
      unknown;

    switch (operation) {
      case "approve":
        result =
          await approveRolloutPlan(
            planID
          );
        break;

      case "cancel":
        result =
          await cancelRolloutPlan(
            planID
          );
        break;

      case "execute": {
        const confirmation =
          text(
            formData,
            "confirmation"
          );

        if (
          confirmation !==
          "EXECUTE"
        ) {
          return {
            ok: false,
            title:
              "Execute rollout",
            message:
              'Перед запуском развёртывания введите EXECUTE точно в таком виде.',
          };
        }

        result =
          await executeRolloutPlan(
            planID
          );
        break;
      }

      default:
        return {
          ok: false,
          title:
            "Rollout",
          message:
            "Неизвестная операция обновления.",
        };
    }

    if (nodeID) {
      revalidatePath(
        `/nodes/${nodeID}`
      );

      revalidatePath(
        `/nodes/${nodeID}/control`
      );

      revalidatePath(
        "/dashboard"
      );
    }

    return {
      ok: true,
      title:
        `Rollout ${operation}`,
      message:
        operation ===
        "execute"
          ? "Запуск обновления запрошен. Перед следующими изменениями проверьте состояние развёртывания."
          : `Rollout ${operation} completed.`,
      data:
        result,
    };
  } catch (error) {
    return errorState(
      `Rollout ${operation}`,
      error
    );
  }
}

export async function evaluateRecoveryAction(
  _previous:
    ControlActionState,
  formData:
    FormData
): Promise<ControlActionState> {
  await requireSession();

  const nodeID =
    text(
      formData,
      "node_id"
    );

  const generation =
    Number(
      text(
        formData,
        "generation"
      )
    );

  if (
    !nodeID ||
    !Number.isInteger(
      generation
    ) ||
    generation < 1
  ) {
    return {
      ok: false,
      title:
        "Проверка восстановления",
      message:
        "Необходимо указать корректную ноду и поколение.",
    };
  }

  try {
    const result =
      await getRecoveryEvaluation(
        nodeID,
        generation
      );

    return {
      ok: true,
      title:
        "Проверка восстановления",
      message:
        `Поколение ${generation} проверено. Изменения восстановления не выполнялись.`,
      data:
        result,
    };
  } catch (error) {
    return errorState(
      "Проверка восстановления",
      error
    );
  }
}

export async function createRecoveryAction(
  _previous:
    ControlActionState,
  formData:
    FormData
): Promise<ControlActionState> {
  await requireSession();

  const nodeID =
    text(
      formData,
      "node_id"
    );

  const generation =
    Number(
      text(
        formData,
        "generation"
      )
    );

  if (
    !nodeID ||
    !Number.isInteger(
      generation
    ) ||
    generation < 1
  ) {
    return {
      ok: false,
      title:
        "Создание попытки восстановления",
      message:
        "Необходимо указать корректную ноду и поколение.",
    };
  }

  try {
    const attempt =
      await createRecoveryAttempt(
        nodeID,
        generation
      );

    return {
      ok: true,
      title:
        "Попытка восстановления создана",
      message:
        `Попытка ${attempt.id} создана. Восстановление ещё не запускалось.`,
      data:
        attempt,
    };
  } catch (error) {
    return errorState(
      "Создание попытки восстановления",
      error
    );
  }
}

export async function mutateRecoveryAction(
  _previous:
    ControlActionState,
  formData:
    FormData
): Promise<ControlActionState> {
  await requireSession();

  const nodeID =
    text(
      formData,
      "node_id"
    );

  const attemptID =
    text(
      formData,
      "attempt_id"
    );

  const operation =
    text(
      formData,
      "operation"
    );

  if (!attemptID) {
    return {
      ok: false,
      title:
        "Recovery",
      message:
        "Не указан ID попытки восстановления.",
    };
  }

  try {
    let result:
      unknown;

    switch (operation) {
      case "approve":
        result =
          await approveRecoveryAttempt(
            attemptID
          );
        break;

      case "cancel":
        result =
          await cancelRecoveryAttempt(
            attemptID
          );
        break;

      case "execute": {
        const confirmation =
          text(
            formData,
            "confirmation"
          );

        if (
          confirmation !==
          "EXECUTE"
        ) {
          return {
            ok: false,
            title:
              "Execute recovery",
            message:
              'Перед запуском восстановления введите EXECUTE точно в таком виде.',
          };
        }

        result =
          await executeRecoveryAttempt(
            attemptID
          );
        break;
      }

      default:
        return {
          ok: false,
          title:
            "Recovery",
          message:
            "Неизвестная операция восстановления.",
        };
    }

    if (nodeID) {
      revalidatePath(
        `/nodes/${nodeID}`
      );

      revalidatePath(
        `/nodes/${nodeID}/control`
      );

      revalidatePath(
        "/dashboard"
      );
    }

    return {
      ok: true,
      title:
        `Recovery ${operation}`,
      message:
        operation ===
        "execute"
          ? "Запуск восстановления запрошен. Проверьте состояние развёртывания и ноды."
          : `Recovery ${operation} completed.`,
      data:
        result,
    };
  } catch (error) {
    return errorState(
      `Recovery ${operation}`,
      error
    );
  }
}
