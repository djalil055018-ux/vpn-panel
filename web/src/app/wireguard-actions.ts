"use server";

import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { createVPNService, getNode, getVPNService, enableVPNService, disableVPNService } from "@/lib/control-plane";
import { agentSupportsWebTransports, agentSupportsNativeWireGuard } from "@/lib/node-runtime";

export async function wireguardServiceAction(_previous: { ok: boolean; message: string }, data: FormData) {
  await requireSession();
  const value = (key: string) => String(data.get(key) ?? "").trim();
  const node = value("node_id"), operation = value("operation");
  try {
    const detail = await getNode(node);
    const runtime = detail.node.runtime_core ?? "xray";
    if (runtime !== "xray" && runtime !== "wireguard") return {ok:false,message:"Выберите ноду WireGuard Native или Xray."};
    if (runtime === "wireguard") {
      if (!agentSupportsNativeWireGuard(detail.node.agent_version) || detail.node.desired_generation === 0) return {ok:false,message:"Нужен совместимый Agent 0.2.28+ и начальная конфигурация WireGuard Native. Для новых нод устанавливайте Agent 0.2.29."};
    } else if (!agentSupportsWebTransports(detail.node.agent_version)) return {ok:false,message:"Требуется агент 0.2.26 или новее."};
    if (operation === "create") {
      const port = Number(value("port")), name = value("name"), address = value("address");
      if (!name || !address || /[\s/@?#]/.test(address) || !Number.isInteger(port) || port < 1 || port > 65535 || port === 10085) return { ok: false, message: "Укажите название, IP или домен и свободный порт от 1 до 65535. Порт 10085 зарезервирован." };
      await createVPNService(node, { name, protocol: "wireguard", listen: "0.0.0.0", port, transport: "udp", security: "wireguard", public_address: address, public_port: port });
    } else {
      const service = await getVPNService(value("service_id"));
      if (service.node_id !== node || service.protocol !== "wireguard") return { ok: false, message: "Сервис не принадлежит выбранной ноде." };
      if (operation === "enable") await enableVPNService(service.id);
      else if (operation === "disable") await disableVPNService(service.id);
      else return { ok: false, message: "Неизвестная операция." };
    }
    revalidatePath(`/nodes/${node}/control`); revalidatePath("/clients");
    return { ok: true, message: operation === "create" ? "WireGuard создан отключённым. Включите сервис и назначьте клиентов в разделе «Клиенты»." : "Настройка отправлена на ноду. Проверьте совпадение поколений." };
  } catch {
    revalidatePath(`/nodes/${node}/control`);
    return { ok: false, message: "Изменение не применено. Проверьте свободный порт, доступность ноды и версию агента." };
  }
}

