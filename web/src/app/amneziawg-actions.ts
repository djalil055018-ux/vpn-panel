"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { isAmneziaWGVersion } from "@/lib/amneziawg";
import { agentSupportsAmneziaWG } from "@/lib/node-runtime";
import { createVPNService, configureAmneziaWG, getNode, getVPNService, enableVPNService, disableVPNService, importReviewedAmneziaWG, approveReviewedAmneziaWG, initializeAmneziaWG } from "@/lib/control-plane";

export async function amneziaWGAction(_previous: {ok: boolean; message: string}, data: FormData) {
  await requireSession();
  const value = (name: string) => String(data.get(name) ?? "").trim();
  const operation = value("operation"), node = value("node_id");
  try {
    if (operation === "import") {
      await importReviewedAmneziaWG(); revalidatePath("/core-updates");
      return {ok:true,message:"Проверенная сборка AmneziaWG добавлена в реестр. Теперь её можно одобрить."};
    }
    if (operation === "approve") {
      await approveReviewedAmneziaWG(); revalidatePath("/core-updates");
      return {ok:true,message:"Проверенная сборка AmneziaWG одобрена."};
    }
    const detail = await getNode(node);
    if (detail.node.runtime_core !== "amneziawg" || detail.node.status === "retired" || !agentSupportsAmneziaWG(detail.node.agent_version)) {
      return {ok:false,message:"Нужна отдельная нода AmneziaWG с установленным агентом 0.2.42 или новее."};
    }
    if (operation === "initialize") {
      await initializeAmneziaWG(node); revalidatePath(`/nodes/${node}/control`);
      return {ok:true,message:"Начальная конфигурация отправлена. Дождитесь применения поколения агентом."};
    }
    if (detail.node.desired_generation === 0) return {ok:false,message:"Сначала отправьте начальную конфигурацию AmneziaWG."};
    const version = value("version");
    if (["create","version"].includes(operation) && !isAmneziaWGVersion(version)) return {ok:false,message:"Выберите версию AmneziaWG из списка."};
    if (operation === "create") {
      const name = value("name"), address = value("address"), port = Number(value("port"));
      if (!name || [...name].length > 200 || !address || address.length > 253 || /[\s/@?#]/u.test(address) || !Number.isInteger(port) || port < 1 || port > 65535 || port === 10085) {
        return {ok:false,message:"Укажите название, публичный IP или домен и свободный UDP-порт от 1 до 65535."};
      }
      const service = await createVPNService(node,{name,protocol:"amneziawg",listen:"0.0.0.0",port,transport:"udp",security:"amneziawg",public_address:address,public_port:port});
      try { await configureAmneziaWG(service.id,version); }
      catch { revalidatePath(`/nodes/${node}/control`); return {ok:false,message:"Сервис создан отключённым, но версия не сохранена. Выберите версию в его карточке перед включением."}; }
    } else {
      const service = await getVPNService(value("service_id"));
      if (service.node_id !== node || service.protocol !== "amneziawg") return {ok:false,message:"Сервис не принадлежит этой ноде AmneziaWG."};
      if (operation === "version") await configureAmneziaWG(service.id,version);
      else if (operation === "enable") await enableVPNService(service.id);
      else if (operation === "disable") await disableVPNService(service.id);
      else return {ok:false,message:"Неизвестная операция."};
    }
    revalidatePath(`/nodes/${node}/control`); revalidatePath("/clients");
    return {ok:true,message:operation === "create" ? "AmneziaWG создан отключённым. Включите сервис и назначьте доступ клиентам или группе." : operation === "version" ? "Версия сохранена. Дождитесь применения поколения и заново импортируйте профили на устройствах." : "Изменение отправлено агенту. Проверьте применённое поколение."};
  } catch {
    if (node) revalidatePath(`/nodes/${node}/control`);
    return {ok:false,message:"Не удалось применить настройку. Проверьте регистрацию ноды, одобренную сборку и свободный порт. На ноде может быть включён один сервис AmneziaWG."};
  }
}
