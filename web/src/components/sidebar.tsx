"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { logoutAction } from "@/app/actions";
import { adminRoleLabels, type AdminRole } from "@/lib/admin-types";
import { NavIcon, type NavIconName } from "@/components/ui/nav-icon";
import { PaukMark } from "@/components/ui/pauk-mark";

type Item = { label: string; href: string; icon: NavIconName; owner?: boolean };
const groups: { name: string; items: Item[] }[] = [
  { name: "Рабочее пространство", items: [
    { label: "Обзор", href: "/dashboard", icon: "dashboard" },
    { label: "Серверы (Смартфоны)", href: "/nodes", icon: "nodes" },
    { label: "Клиенты", href: "/clients", icon: "clients" },
    { label: "Группы доступа", href: "/access-plans", icon: "shield" },
    { label: "Каскады", href: "/cascades", icon: "cascade" },
    { label: "Автоподключение", href: "/auto-profile", icon: "activity" },
    { label: "Биллинг", href: "/billing", icon: "billing" },
    { label: "Партнёры", href: "/partners", icon: "clients" },
  ] },
  { name: "Инфраструктура", items: [
    { label: "Состояние системы", href: "/operations", icon: "activity" },
    { label: "Обновления ядер", href: "/core-updates", icon: "core" },
    { label: "Агенты серверов", href: "/agent-updates", icon: "nodes" },
    { label: "Развёртывания", href: "/deployments", icon: "deployments" },
    { label: "Сертификаты", href: "/certificates", icon: "shield" },
    { label: "Инциденты", href: "/incidents", icon: "activity" },
    { label: "Восстановление", href: "/recovery", icon: "recovery" },
  ] },
  { name: "Управление", items: [
    { label: "Оформление", href: "/branding", icon: "settings" },
    { label: "Лимиты", href: "/limits", icon: "settings" },
    { label: "Доступ к API", href: "/api-access", icon: "core" },
    { label: "Webhooks", href: "/webhooks", icon: "core" },
    { label: "Журнал действий", href: "/audit", icon: "deployments" },
    { label: "Администраторы", href: "/administrators", icon: "clients", owner: true },
    { label: "Перенос Remnawave", href: "/migrations/remnawave", icon: "deployments", owner: true },
    { label: "Настройки", href: "/settings", icon: "settings" },
  ] },
];
export function Sidebar({ user, role }: { user: string; role: AdminRole }) {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  return <aside className={`sidebar${open ? " is-open" : ""}`}>
    <div className="sidebar-heading">
      <Link className="brand" href="/dashboard" aria-label="PAUK — обзор" onClick={() => setOpen(false)}>
        <div className="brand-mark"><PaukMark /></div>
        <div className="brand-copy"><strong>PAUK<span className="brand-period">.</span></strong><span>VPN management</span></div>
      </Link>
      <button type="button" className="mobile-menu" aria-expanded={open} aria-controls="workspace-navigation" onClick={() => setOpen(!open)}>{open ? "Закрыть" : "Меню"}<span aria-hidden="true">{open ? "×" : "☰"}</span></button>
    </div>
    <nav id="workspace-navigation" className="nav" aria-label="Основная навигация">
      {groups.map(group => <div className="nav-group" key={group.name}>
        <p className="nav-heading">{group.name}</p>
        {group.items.filter(item => !item.owner || role === "owner").map(item => {
          const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
          return <Link key={item.href} href={item.href} onClick={() => setOpen(false)} className={`nav-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined}>
            <span className="nav-icon"><NavIcon name={item.icon} width={19} height={19} /></span><span className="nav-label">{item.label}</span>
          </Link>;
        })}
      </div>)}
    </nav>
    <div className="sidebar-bottom">
      <Link href="/account" className="user-box" onClick={() => setOpen(false)}><span className="user-avatar">{user.slice(0, 1).toUpperCase()}</span><div className="user-copy"><strong>{user}</strong><span>{adminRoleLabels[role]}</span></div><span aria-hidden="true">↗</span></Link>
      <form action={logoutAction}><button type="submit" className="sidebar-signout">Выйти из аккаунта</button></form>
    </div>
  </aside>;
}
