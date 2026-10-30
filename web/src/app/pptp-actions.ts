"use server";
import { revalidatePath } from "next/cache";
import { unstable_rethrow } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { createVPNService, getNode, getVPNService, enableVPNService, disableVPNService, rotatePPTPCredential } from "@/lib/control-plane";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function pptpServiceAction(_previous: {ok:boolean;message:string},data:FormData) {
  const session=await requireSession();
  if(session.role==="monitor") return {ok:false,message:"Для изменения PPTP нужны права администратора."};
  const value=(key:string)=>String(data.get(key)??"").trim();
  const node=value("node_id"),operation=value("operation");
  if(!uuid.test(node)) return {ok:false,message:"Не указана нода."};
  try {
    const detail=await getNode(node);
    if(detail.node.runtime_core!=="pptp" || detail.node.desired_generation===0) return {ok:false,message:"Сначала подготовьте отдельную ноду PPTP и её начальную конфигурацию."};
    if(operation==="create") {
      const name=value("name"),address=value("address");
      if(!name || name.length>200 || !address || address.length>253 || /[\s/:@?#]/.test(address)) return {ok:false,message:"Укажите название и домен либо IPv4-адрес ноды."};
      await createVPNService(node,{name,protocol:"pptp",listen:"0.0.0.0",port:1723,transport:"tcp,gre",security:"mppe",public_address:address,public_port:1723});
    } else {
      if(!uuid.test(value("service_id"))) return {ok:false,message:"Не указан сервис."};
      const service=await getVPNService(value("service_id"));
      if(service.node_id!==node || service.protocol!=="pptp") return {ok:false,message:"Сервис не принадлежит выбранной ноде."};
      if(operation==="enable") await enableVPNService(service.id);
      else if(operation==="disable") await disableVPNService(service.id);
      else return {ok:false,message:"Неизвестная операция."};
    }
    revalidatePath(`/nodes/${node}/control`);revalidatePath("/clients");
    return {ok:true,message:operation==="create"?"PPTP создан отключённым. Включите сервис и назначьте клиентов. Данные подключения доступны в разделе «Клиенты».":"Настройка отправлена на ноду. Дождитесь совпадения поколений."};
  } catch(error) {
    unstable_rethrow(error);
    return {ok:false,message:"Изменение не применено. Проверьте состояние ноды и отсутствие другого включённого PPTP-сервиса."};
  }
}

export async function rotatePPTPCredentialAction(client:string,service:string) {
  const session=await requireSession();
  if(session.role==="monitor") return {ok:false,message:"Для смены пароля нужны права администратора."};
  if(!uuid.test(client)||!uuid.test(service)) return {ok:false,message:"Не указано подключение."};
  try {
    await rotatePPTPCredential(service,client);
    revalidatePath("/clients");
    return {ok:true,message:"Пароль заменён. Старый туннель отключится после применения конфигурации. Скачайте обновлённую инструкцию."};
  } catch(error) {
    unstable_rethrow(error);
    return {ok:false,message:"Не удалось подтвердить смену пароля. Обновите данные подключения перед повторной попыткой."};
  }
}
