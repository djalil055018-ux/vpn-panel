"use client";
import Link from "next/link";
import { useActionState } from "react";
import { wireguardSetupAction } from "@/app/wireguard-setup-actions";

function Action({operation,node="",children}:{operation:string;node?:string;children:React.ReactNode}) {
  const [state,action,pending]=useActionState(wireguardSetupAction,{ok:false,message:""});
  return <form action={action}><input type="hidden" name="operation" value={operation}/><input type="hidden" name="node_id" value={node}/><button className="button primary" disabled={pending}>{pending?"Выполнение…":children}</button>{state.message&&<p role="status" className={`plan-feedback ${state.ok?"":"error"}`}>{state.message}</p>}</form>;
}
export function WireGuardReleaseManager(){
  return <section className="panel"><div className="panel-header"><div><h2>Проверенная сборка WireGuard</h2><p>WireGuard Tools 1.0.20210914 для Ubuntu 24.04 amd64. Для новых Native WireGuard нод используйте Agent 0.2.29; минимум совместимости — 0.2.28. Сначала добавьте сборку в реестр, затем одобрите её. Пакет устанавливается при подготовке отдельной ноды.</p></div></div><div className="plan-form"><Action operation="import">Добавить проверенную сборку</Action><Action operation="approve">Одобрить проверенную сборку</Action></div></section>;
}
export function InitializeWireGuard({node,registered}:{node:string;registered:boolean}){
  return <section className="panel"><div className="panel-header"><div><h2>Подготовить WireGuard Native</h2><p>Начальная конфигурация подготовит ядро без выдачи клиентского доступа. После её применения можно включить WireGuard-сервис и назначить тарифы.</p></div></div><div className="plan-form">{registered?<Action node={node} operation="initialize">Отправить начальную конфигурацию</Action>:<p>Сначала установите агент и дождитесь регистрации ноды.</p>}<Link className="button" href="/core-updates">Проверить сборку в реестре</Link></div></section>;
}
