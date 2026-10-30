"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { configureVPNServiceTLS, createVPNService, getNodeCertificates, getNode, getVPNService, enableVPNService, disableVPNService } from "@/lib/control-plane";
import { agentSupportsWebTransports, tlsProtocol } from "@/lib/node-runtime";

export async function tlsServiceAction(_previous: { ok: boolean; message: string }, data: FormData) {
  await requireSession();
  const value = (key: string) => String(data.get(key) ?? "").trim();
  const node = value("node_id"), operation = value("operation"), certificate = value("certificate_id");
  let service = value("service_id"), created = false;
  try {
    const detail = await getNode(node);
    const runtime = detail.node.runtime_core ?? "xray";
    if (operation !== "create" && (await getVPNService(service)).node_id !== node) {
      return { ok: false, message: "Сервис не принадлежит выбранной ноде." };
    }
    if (operation === "create" || operation === "certificate") {
      const selected = (await getNodeCertificates(node)).find(c => c.id === certificate && c.environment === "production" && ["active", "renewing"].includes(c.status) && c.not_after && Date.parse(c.not_after) > Date.now());
      if (!selected) return { ok: false, message: "Выберите действующий production-сертификат этой ноды." };
      if (operation === "create") {
        const port = Number(value("port")), name = value("name"), selection = tlsProtocol(runtime, value("protocol"));
        if (!selection) return { ok: false, message: "Выбранный протокол не поддерживается ядром этой ноды." };
        const { protocol, transport } = selection;
        if (["ws", "grpc"].includes(transport) && !agentSupportsWebTransports(detail.node.agent_version)) return { ok: false, message: "WebSocket и gRPC требуют агента 0.2.26 или новее." };
        if (!name || !Number.isInteger(port) || port < 1 || port > 65535) return { ok: false, message: "Укажите название и порт от 1 до 65535." };
        const result = await createVPNService(node, { name, protocol, listen: "0.0.0.0", port, transport, security: "tls", public_address: selected.domain, public_port: port });
        service = result.id; created = true;
      }
      await configureVPNServiceTLS(service, certificate);
    } else if (operation === "enable") await enableVPNService(service);
    else if (operation === "disable") await disableVPNService(service);
    else return { ok: false, message: "Неизвестная операция." };
    revalidatePath(`/nodes/${node}/control`); revalidatePath("/clients"); revalidatePath("/certificates");
    return { ok: true, message: operation === "create" ? "TLS-сервис создан отключённым. Включите его, когда будете готовы назначать доступ." : operation === "certificate" ? "Сертификат сохранён. Для включённого сервиса создано новое поколение настройки." : "Изменение отправлено на ноду. Проверьте совпадение поколений." };
  } catch {
    revalidatePath(`/nodes/${node}/control`);
    return { ok: false, message: created ? "Сервис создан отключённым. Не удалось привязать сертификат — повторите выбор в его карточке." : "Изменение не применено. Проверьте сертификат, свободный порт и совместимость агента. На ноде Hysteria можно включить только один сервис." };
  }
}
