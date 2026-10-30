"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { approveXrayRelease, ControlPlaneError, getCoreReleases, importLatestXray, pauseAgentFleet, retryAgentUpdate, startAgentFleet, startXrayUpdate } from "@/lib/control-plane";
import type { UpdateActionState } from "@/lib/update-types";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function value(data: FormData, key: string) { return String(data.get(key) ?? "").trim(); }
export async function platformUpdateAction(_previous: UpdateActionState, data: FormData): Promise<UpdateActionState> {
  const session = await requireSession();
  const operation = value(data, "operation");
  if (session.role === "monitor" || (operation.startsWith("agent-") && session.role !== "owner")) return { ok: false, message: "Для этого действия недостаточно прав." };
  const node = value(data, "node_id"), id = value(data, "id"), requestKey = value(data, "request_key");
  const prerelease = data.get("accept_prerelease") === "yes";
  try {
    let message: string;
    if (operation === "xray-discover") {
      const { release } = await importLatestXray();
      message = `В реестре доступен Xray ${release.version}${release.upstream_prerelease ? " — предварительный выпуск" : ""}.`;
    } else if (operation === "xray-approve") {
      if (!uuid.test(id)) return { ok: false, message: "Выберите версию Xray." };
      const release = (await getCoreReleases()).find(r => r.id === id && (r.type ?? r.core_type) === "xray" && !r.revoked);
      if (!release || (release.upstream_prerelease && !prerelease)) return { ok: false, message: "Подтвердите использование предварительного выпуска." };
      if (!release.approved) await approveXrayRelease(id);
      message = `Xray ${release.version} одобрен. Выберите ноду для установки.`;
    } else if (operation === "xray-install") {
      if (!uuid.test(node) || !uuid.test(id) || !uuid.test(requestKey)) return { ok: false, message: "Обновите страницу и выберите ноду и версию." };
      const result = await startXrayUpdate(node, id, requestKey, prerelease);
      message = `Начата установка Xray ${result.target_version}. Состояние обновится автоматически.`;
    } else if (operation === "agent-start") {
      if (!uuid.test(node) || !uuid.test(requestKey)) return { ok: false, message: "Обновите страницу и выберите ноду." };
      await startAgentFleet(node, requestKey); message = "Обновление запущено. Остальные ноды продолжат обновляться по очереди.";
    } else if (operation === "agent-pause" || operation === "agent-resume") {
      if (!uuid.test(id)) return { ok: false, message: "Выберите текущее обновление." };
      await pauseAgentFleet(id, operation === "agent-pause");
      message = operation === "agent-pause" ? "Очередь приостановлена. Уже начатая установка завершится." : "Очередь продолжена.";
    } else if (operation === "agent-retry") {
      if (!uuid.test(id)) return { ok: false, message: "Выберите ноду с ошибкой." };
      await retryAgentUpdate(id); message = "Повторная проверка и установка поставлены первыми в очередь.";
    } else return { ok: false, message: "Неизвестное действие." };
    for (const path of ["/agent-updates", "/core-updates", "/nodes"]) revalidatePath(path);
    if (uuid.test(node)) { revalidatePath(`/nodes/${node}`); revalidatePath(`/nodes/${node}/control`); }
    return { ok: true, message };
  } catch (error) {
    return { ok: false, message: error instanceof ControlPlaneError && error.status === 409 ? "Состояние изменилось. Проверьте доступность ноды, одобрение версии и текущее обновление; затем повторите действие." : "Не удалось завершить запрос. Проверьте текущее состояние перед повтором." };
  }
}
