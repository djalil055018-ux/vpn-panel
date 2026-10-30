"use client";
import Link from "next/link";
import { useActionState } from "react";
import { hysteriaSetupAction } from "@/app/hysteria-actions";

function Action({operation,node="",children}:{operation:string;node?:string;children:React.ReactNode}) {
  const [state,action,pending]=useActionState(hysteriaSetupAction,{ok:false,message:""});
  return <form action={action}><input type="hidden" name="operation" value={operation}/><input type="hidden" name="node_id" value={node}/><button className="button primary" disabled={pending}>{pending?"Выполнение…":children}</button>{state.message&&<p role="status" className={`plan-feedback ${state.ok?"":"error"}`}>{state.message}</p>}</form>;
}
export function HysteriaReleaseManager(){
  return <section className="panel"><div className="panel-header"><div><h2>Проверенная сборка Hysteria 2</h2><p>Версия 2.13.0 для Linux amd64; требуется агент 0.2.43 или новее. Действующие ноды с 2.12.2 сохраняют свою сборку. Сначала добавьте сборку в реестр, затем одобрите её. Обновления нод запускаются отдельно.</p></div></div><div className="plan-form"><Action operation="import">Добавить проверенную сборку</Action><Action operation="approve">Одобрить проверенную сборку</Action></div></section>;
}
export function InitializeHysteria({node,registered}:{node:string;registered:boolean}){
  return <section className="panel"><div className="panel-header"><div><h2>Подготовить Hysteria</h2><p>Начальная конфигурация подготовит ядро без выдачи клиентского доступа. После её применения можно включить TLS-сервис и назначить тарифы.</p></div></div><div className="plan-form">{registered?<Action node={node} operation="initialize">Отправить начальную конфигурацию</Action>:<p>Сначала установите агент и дождитесь регистрации ноды.</p>}<Link className="button" href="/core-updates">Проверить сборку в реестре</Link></div></section>;
}
