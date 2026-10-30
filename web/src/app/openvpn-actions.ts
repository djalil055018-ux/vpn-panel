"use server";
import { revalidatePath } from "next/cache";
import { requireSession } from "@/lib/auth";
import { createVPNService, getNode, getVPNService, enableVPNService, disableVPNService } from "@/lib/control-plane";

export async function openvpnServiceAction(_previous: {ok:boolean;message:string},data:FormData) {
  await requireSession();
  const value=(key:string)=>String(data.get(key)??"").trim();
  const node=value("node_id"),operation=value("operation");
  try {
    const detail=await getNode(node);
    if(detail.node.runtime_core!=="openvpn" || detail.node.desired_generation===0) return {ok:false,message:"Сначала подготовьте отдельную ноду OpenVPN и её начальную конфигурацию."};
    if(operation==="create") {
      const name=value("name"),address=value("address"),transport=value("transport"),port=Number(value("port"));
      if(!name || !address || /[\s/@?#]/.test(address) || !["udp","tcp"].includes(transport) || !Number.isInteger(port) || port<1 || port>65535) return {ok:false,message:"Укажите название, адрес ноды, транспорт и свободный порт от 1 до 65535."};
      await createVPNService(node,{name,protocol:"openvpn",listen:"0.0.0.0",port,transport,security:"tls",public_address:address,public_port:port});
    } else {
      const service=await getVPNService(value("service_id"));
      if(service.node_id!==node || service.protocol!=="openvpn") return {ok:false,message:"Сервис не принадлежит выбранной ноде."};
      if(operation==="enable") await enableVPNService(service.id);
      else if(operation==="disable") await disableVPNService(service.id);
      else return {ok:false,message:"Неизвестная операция."};
    }
    revalidatePath(`/nodes/${node}/control`);revalidatePath("/clients");
    return {ok:true,message:operation==="create"?"OpenVPN создан отключённым. Включите сервис и назначьте клиентов. Профили доступны в разделе «Клиенты».":"Настройка отправлена на ноду. Дождитесь совпадения поколений."};
  } catch {return {ok:false,message:"Изменение не применено. Проверьте доступность ноды, свободный порт и отсутствие другого включённого OpenVPN-сервиса."};}
}
