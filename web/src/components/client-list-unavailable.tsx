"use client";

import { useTransition } from "react";
import { useRouter } from "next/navigation";
import { NavIcon } from "@/components/ui/nav-icon";

export function ClientListUnavailable() {
  const router = useRouter();
  const [pending, refresh] = useTransition();
  return <>
    <header className="page-header"><div><div className="eyebrow">РАБОЧЕЕ ПРОСТРАНСТВО</div><h1>Клиенты</h1></div></header>
    <section className="panel empty-state" role="alert">
      <NavIcon name="clients" width={36} height={36}/>
      <h2>Не удалось загрузить клиентов</h2>
      <p>Сервис временно не вернул полный список. Обновите страницу, чтобы получить актуальные данные.</p>
      <button type="button" className="button primary" disabled={pending} onClick={() => refresh(() => router.refresh())}>{pending ? "Загрузка…" : "Повторить загрузку"}</button>
    </section>
  </>;
}
