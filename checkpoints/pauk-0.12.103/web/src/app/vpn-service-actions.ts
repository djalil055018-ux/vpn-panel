"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { ControlPlaneError, deleteVPNService, getNode, getVPNService, updateVPNServiceSettings } from "@/lib/control-plane";
import { agentSupportsVLESSTLS, agentSupportsVLESSXHTTP, agentSupportsWebTransports, xraySupportsXHTTP } from "@/lib/node-runtime";

export type VPNServiceSettingsActionState = {
  ok: boolean;
  message: string;
};

export async function updateVPNServiceSettingsAction(
  _previous: VPNServiceSettingsActionState,
  data: FormData,
): Promise<VPNServiceSettingsActionState> {
  await requireSession();

  const value = (key: string) => String(data.get(key) ?? "").trim();
  const nodeID = value("node_id");
  const serviceID = value("service_id");
  const name = value("name");
  const listen = value("listen");
  const port = Number(value("port"));
  const publicAddress = value("public_address");
  const publicPort = Number(value("public_port"));
  const requestedTransport = value("transport");

  if (!nodeID || !serviceID) {
    return { ok: false, message: "Не удалось определить ноду или конфигурацию." };
  }
  if (!name || [...name].length > 200 || /[\p{Cc}\u2028\u2029]/u.test(name)) {
    return { ok: false, message: "Введите название в одну строку, до 200 символов." };
  }
  if (!listen || listen.length > 45) {
    return { ok: false, message: "Укажите IPv4 или IPv6 адрес прослушивания." };
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, message: "Порт на сервере должен быть от 1 до 65535." };
  }
  if (!publicAddress || publicAddress.length > 253 || /[\s/@?#]/u.test(publicAddress)) {
    return { ok: false, message: "Укажите домен или IP без протокола, пути и параметров ссылки." };
  }
  if (!Number.isInteger(publicPort) || publicPort < 1 || publicPort > 65535) {
    return { ok: false, message: "Публичный порт должен быть от 1 до 65535." };
  }

  try {
    const [detail, service] = await Promise.all([getNode(nodeID), getVPNService(serviceID)]);
    if (detail.node.status === "retired" || service.node_id !== nodeID) {
      return { ok: false, message: "Конфигурация не принадлежит выбранной ноде или уже выведена из эксплуатации." };
    }

    let transport = service.transport;
    if (service.protocol === "openvpn") {
      transport = requestedTransport || service.transport;
    } else if (service.protocol === "vless" && service.security === "tls") {
      transport = requestedTransport || service.transport;
      if (!["tcp", "xhttp", "ws", "grpc"].includes(transport)) {
        return { ok: false, message: "Выберите поддерживаемый транспорт VLESS TLS." };
      }
      if (transport !== service.transport && transport === "tcp" && !agentSupportsVLESSTLS(detail.node.agent_version)) {
        return { ok: false, message: "TCP TLS требует агента 0.2.15 или новее." };
      }
      if (transport !== service.transport && transport === "xhttp" && !agentSupportsVLESSXHTTP(detail.node.agent_version)) {
        return { ok: false, message: "XHTTP требует агента 0.2.17 или новее." };
      }
      if (transport !== service.transport && ["ws", "grpc"].includes(transport) && !agentSupportsWebTransports(detail.node.agent_version)) {
        return { ok: false, message: "WebSocket и gRPC требуют агента 0.2.26 или новее. Обновите агент сервера и повторите." };
      }
      if (transport !== service.transport && transport === "xhttp" && !xraySupportsXHTTP(detail.runtime.current_core_version)) {
        return { ok: false, message: "XHTTP требует Xray 26.7.28 или новее. Обновите ядро сервера и повторите." };
      }
    }

    const result = await updateVPNServiceSettings(serviceID, {
      name,
      listen,
      port: service.protocol === "pptp" ? 1723 : port,
      transport,
      public_address: publicAddress,
      public_port: publicPort,
    });

    revalidatePath(`/nodes/${nodeID}/control`);
    revalidatePath("/clients");
    return {
      ok: true,
      message: `Изменения сохранены, узлу назначена generation ${result.generation}. После её применения обновите подписку в приложении; для нового порта проверьте firewall и перенаправление на роутере.`,
    };
  } catch (error) {
    revalidatePath(`/nodes/${nodeID}/control`);
    if (error instanceof ControlPlaneError && error.status === 400) {
      return { ok: false, message: error.body.includes("transport") ? "Выбранный транспорт не поддерживается этой конфигурацией." : "Проверьте адрес и порт. Для PPTP порт фиксирован на 1723." };
    }
    if (error instanceof ControlPlaneError && error.status === 409 && error.body.includes("newer node agent")) return { ok: false, message: "Для этого транспорта обновите агент сервера до поддерживаемой версии и повторите." };
    if (error instanceof ControlPlaneError && error.status === 409 && error.body.includes("XHTTP requires Xray")) return { ok: false, message: "Для XHTTP требуется Xray 26.7.28 или новее. Обновите ядро сервера и повторите." };
    if (error instanceof ControlPlaneError && error.status === 409) {
      return { ok: false, message: "Не удалось применить изменения: этот адрес и порт уже заняты либо конфигурация несовместима с текущим состоянием узла." };
    }
    return {
      ok: false,
      message: "Не удалось сохранить конфигурацию. Проверьте данные и доступность панели.",
    };
  }
}

export type DeleteVPNServiceActionState = { ok: boolean; message: string };

export async function deleteVPNServiceAction(
  _previous: DeleteVPNServiceActionState,
  data: FormData,
): Promise<DeleteVPNServiceActionState> {
  const session = await requireSession();
  if (session.role !== "owner") return { ok: false, message: "Удалять протоколы может только владелец панели." };
  const serviceID = String(data.get("service_id") ?? "").trim();
  const name = String(data.get("confirm_name") ?? "").trim();
  const confirmed = data.get("confirm_delete") === "yes";
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(serviceID) || !name || name.length > 200 || !confirmed) {
    return { ok: false, message: "Введите точное имя конфигурации и подтвердите удаление." };
  }
  try {
    const result = await deleteVPNService(serviceID, name);
    if (!result.deleted || result.service_id !== serviceID) return { ok: false, message: "Удаление не подтверждено. Обновите страницу и проверьте конфигурацию." };
    for (const path of ["/nodes", "/clients", "/access-plans", "/cascades", `/nodes/${result.node_id}`, `/nodes/${result.node_id}/control`]) revalidatePath(path);
    return { ok: true, message: `Конфигурация удалена; узел применит generation ${result.generation}. Профиль убран из ${result.affected_clients} подписок и ${result.affected_plans} тарифов.` };
  } catch (error) {
    if (error instanceof ControlPlaneError) {
      if (error.status === 403) return { ok: false, message: "Недостаточно прав: удалять протокол может только владелец панели." };
      if (error.status === 404) return { ok: false, message: "Конфигурация не найдена. Обновите страницу." };
      if (error.status === 409) return { ok: false, message: "Удаление не выполнено: сначала уберите протокол из каскада или импортированной подписки либо дождитесь окончания обновления узла." };
    }
    return { ok: false, message: "Не удалось удалить конфигурацию. Обновите страницу и проверьте состояние узла." };
  }
}
