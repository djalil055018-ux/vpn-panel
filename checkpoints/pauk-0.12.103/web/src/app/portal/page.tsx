import Link from "next/link";
import type { CSSProperties } from "react";
import { brandAccents, type TenantBranding } from "@/lib/branding-values";
import { BrandingForm } from "@/components/branding-form";
import { AutoProfileForm, AutoProfileHelp } from "@/components/auto-profile-form";
import type { AutoProfileSettings } from "@/lib/auto-profile-values";
import { randomUUID } from "node:crypto";
import { redirect } from "next/navigation";
import { portalFetch, portalIdentity, PortalError, type PortalClient, type PortalClientUsage, type PortalPlan, type PortalService } from "@/lib/portal-api";
import { portalLogoutAction } from "@/app/portal/actions";
import { TenantPortal } from "@/components/tenant-portal";
import { PortalBilling } from "@/components/portal-billing";
import type { BillingOffer, BillingInvoice } from "@/lib/billing-values";

import { ResellerManagement } from "@/components/reseller-management";
import type { ResellerChild, ResellerCredential } from "@/lib/reseller-values";

export const dynamic = "force-dynamic";
async function loadPortal() {
  const identity = await portalIdentity();
  const limits = await portalFetch<import("@/lib/tenant-limit-values").TenantLimits>("/limits");
  const [clients, listing, services, offers, invoices, branding] = await Promise.all([portalFetch<{ clients: PortalClient[] }>("/clients"), portalFetch<{ plans: { id: string }[] }>("/access-plans"), portalFetch<{ services: PortalService[] }>("/services"), portalFetch<{ offers: BillingOffer[] }>("/offers"), portalFetch<{ invoices: BillingInvoice[] }>("/invoices"), portalFetch<TenantBranding>("/branding")]);
  const usages = await Promise.all(clients.clients.map(client => portalFetch<PortalClientUsage>(`/clients/${client.id}/usage`)));
  const plans = await Promise.all(listing.plans.map(plan => portalFetch<PortalPlan>(`/access-plans/${plan.id}`)));
  const children = identity.role === "reseller" ? (await portalFetch<{ children: ResellerChild[] }>("/children")).children : [];
  await Promise.all(children.map(async child => { child.credentials = (await portalFetch<{ credentials: ResellerCredential[] }>(`/children/${child.id}/api-tokens`)).credentials; }));
  const autoProfile = identity.role === "operator" ? await portalFetch<AutoProfileSettings>("/auto-profile") : null;
  return { limits, children, at: Date.now(), identity, branding, autoProfile, clients: clients.clients, usages, plans, services: services.services, offers: offers.offers, invoices: invoices.invoices, requestKey: randomUUID() };
}
export default async function PortalPage() {
  let data = null, unauthorized = false;
  try { data = await loadPortal(); } catch (error) { unauthorized = error instanceof PortalError && error.status === 401; }
  if (unauthorized) redirect("/portal/login");
  if (!data) return <main className="portal-shell"><section className="panel portal-card"><h1>Кабинет временно недоступен</h1><p>Обновите страницу немного позже.</p><Link href="/portal" className="button primary">Обновить</Link></section></main>;
  const operator = data.identity.role === "operator";
  return <main className="portal-shell branded-portal" style={{ "--brand-accent": brandAccents.find(accent => accent.value === data.branding.accent)?.color ?? "#88b4ff" } as CSSProperties}><header className="portal-header"><div><div className="eyebrow">{data.branding.display_name}</div><h1>{data.identity.role === "reseller" ? "Кабинет партнёра" : "Кабинет владельца"}</h1><p>{data.branding.tagline || (data.identity.role === "reseller" ? "Создание владельцев и управление делегированными ключами." : operator ? "Управление клиентами, тарифами и подписками." : "Режим просмотра: клиенты и тарифы вашего владельца.")}</p></div><form action={portalLogoutAction}><button className="button ghost">Выйти</button></form></header><nav className="portal-nav" aria-label="Разделы кабинета">{data.identity.role === "reseller" && <a href="#children">Владельцы</a>}<a href="#clients">Клиенты</a><a href="#plans">Тарифы</a><a href="#billing">Счета</a>{operator && <a href="#auto-profile">Автоподключение</a>}<Link href="/portal">Обновить</Link>{data.branding.support_url && <a href={data.branding.support_url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">{data.branding.support_label}</a>}<span>{data.identity.role === "reseller" ? "Партнёр" : operator ? "Управление доступом" : "Только просмотр"}</span></nav><div className="portal-summary"><section className="panel"><span>Активные клиенты</span><strong>{data.clients.filter(client => client.effective_status === "active").length}</strong></section><section className="panel"><span>Тарифы</span><strong>{data.plans.length}</strong></section><section className="panel"><span>Доступные сервисы</span><strong>{data.services.filter(service => service.enabled).length}</strong></section></div>{data.identity.role === "reseller" && <ResellerManagement owners={data.children} at={data.at} />}<p className="portal-note">Лимиты владельца: клиенты {data.limits.clients} / {data.limits.max_clients || "без ограничения"}; тарифы {data.limits.plans} / {data.limits.max_plans || "без ограничения"}. Изменяет администратор.</p><TenantPortal clients={data.clients} usages={data.usages} plans={data.plans} services={data.services} operator={operator} connectionRevision={data.requestKey} /><PortalBilling offers={data.offers} invoices={data.invoices} clients={data.clients.filter(client => !client.remnawave_hold)} operator={operator} requestKey={data.requestKey} />{operator && data.autoProfile && <details id="auto-profile" className="panel portal-create"><summary>Автоподключение</summary><AutoProfileForm settings={data.autoProfile} portal /><AutoProfileHelp /></details>}{operator && <details className="panel portal-create"><summary>Оформление кабинета</summary><BrandingForm branding={data.branding} portal /></details>}<footer className="portal-footer">Сроки указаны по Москве. Изменение доступа требует применения на нодах; истечение срока проверяется каждую минуту.</footer></main>;
}
