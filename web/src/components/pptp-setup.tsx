"use client";
import Link from "next/link";
import { useActionState } from "react";
import { pptpSetupAction } from "@/app/pptp-setup-actions";

function Action({operation,node="",children}:{operation:string;node?:string;children:React.ReactNode}) {
  const [state,action,pending]=useActionState(pptpSetupAction,{ok:false,message:""});
  return <form action={action}><input type="hidden" name="operation" value={operation}/><input type="hidden" name="node_id" value={node}/><button className="button primary" disabled={pending}>{pending?"Выполнение…":children}</button>{state.message&&<p role="status" className={`plan-feedback ${state.ok?"":"error"}`}>{state.message}</p>}</form>;
}
export function PPTPReleaseManager(){
  return <section className="panel"><div className="panel-header"><div><h2>Проверенная сборка PPTP</h2><p>Accel-PPP 1.14.0-platform.1 для Ubuntu 24.04 amd64. Сначала добавьте сборку в реестр, затем одобрите её. Пакет устанавливается при подготовке отдельной ноды.</p></div></div><div className="plan-form"><Action operation="import">Добавить проверенную сборку</Action><Action operation="approve">Одобрить проверенную сборку</Action></div></section>;
}
export function InitializePPTP({node,registered}:{node:string;registered:boolean}){
  return <section className="panel"><div className="panel-header"><div><h2>Подготовить PPTP</h2><p>Начальная конфигурация подготовит ядро без выдачи клиентского доступа. После её применения можно включить PPTP-сервис и назначить тарифы.</p></div></div><div className="plan-form">{registered?<Action node={node} operation="initialize">Отправить начальную конфигурацию</Action>:<p>Сначала установите агент и дождитесь регистрации ноды.</p>}<Link className="button" href="/core-updates">Проверить сборку в реестре</Link></div></section>;
}
