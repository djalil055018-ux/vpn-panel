"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { CustomerPaymentCancel } from "@/components/customer-payment-cancel";
import { CustomerSubscriptionDelete } from "@/components/customer-subscription-delete";
import { PurchaseRequests } from "@/lib/customer-purchase-requests";
import type { PublicSubscription } from "@/lib/public-subscription";
import { PlanCheckout, PaymentDetails, pendingPayment, money, type Account, type Plan, type Order, type PurchaseIntent } from "@/components/customer-commerce";
import { mergePayment, subscriptionName, subscriptionExpiry, orderPurpose } from "@/lib/customer-commerce-state";
import { trafficLabel } from "@/lib/public-subscription";

type Overview = { profile: { name: string; telegram?: string; mode?: string }; subscriptions: Account[]; plans: Plan[]; gateways: { code: string; name: string }[]; features: { sales: boolean; sales_message?: string; trial: boolean; trial_days: number; devices: boolean; revoke: boolean; extra_device: boolean; extra_device_rub: number; affiliate: boolean } };
type Device = { hwid: string; deviceModel?: string; platform?: string; osVersion?: string; createdAt?: string };
type Referral = { link: string; invited: number; rewarded: number; pending_days: number; fee_bps: number; share_bps: number; hold_days: number; balances: { currency: string; minor_scale: number; available_minor: number; hold_minor: number }[]; shop?: { name: string; status: string }; withdrawals: { id: number; amount_minor: number; scale: number; currency: string; status: string }[] };
type Ticket = { id: string; subject: string; status: string; preview?: string; messages?: { sender: string; text: string; created_at: string }[] };
type Tab = "subscriptions" | "plans" | "payments" | "devices" | "bonuses" | "support";
const tabs: { id: Tab; label: string; icon: string }[] = [
  { id: "subscriptions", label: "Мои подписки", icon: "◈" }, { id: "plans", label: "Тарифы и оплата", icon: "↗" },
  { id: "payments", label: "Платежи", icon: "▤" }, { id: "devices", label: "Устройства", icon: "▣" },
  { id: "bonuses", label: "Бонусы", icon: "✧" }, { id: "support", label: "Помощь", icon: "?" },
];
const statuses: Record<string, string> = { DELETING: "Удаление не завершено", ACTIVE: "Активна", EXPIRED: "Срок истёк", DISABLED: "Приостановлена", LIMITED: "Лимит трафика", UNKNOWN: "Данные обновляются", PENDING: "Ожидает оплаты", PAYMENT_PENDING: "Ожидает оплаты", WAITING_PAYMENT: "Ожидает оплаты", WAITING_PROOF: "Ожидается чек", PAYMENT_REJECTED: "Чек не подтверждён", PAYMENT_REVIEW: "Чек на проверке", PAID: "Оплата получена", APPLIED: "Выполнен", APPLY_FAILED: "Оплачен · активация задерживается", PAYMENT_MISMATCH: "Нужна проверка оплаты", CANCELED: "Отменён", PAID_AFTER_CANCEL: "Оплата на проверке", REFUNDED: "Возвращён", REQUESTED: "На рассмотрении", APPROVED: "Одобрено", REJECTED: "Отклонено", OPEN: "Открыто", IN_PROGRESS: "В работе", CLOSED: "Закрыто" };
const gatewayPriority: Record<string, number> = { YOOMONEY_RUB: 0, TELEGRAM_STARS: 1 };
const statusLabel = (status: string) => statuses[status] || status;
const date = (value?: string) => value ? new Intl.DateTimeFormat("ru", { day: "numeric", month: "short", year: "numeric" }).format(new Date(value)) : "—";
function safeLink(value?: string): string | undefined { try { const url = new URL(value || ""); return url.protocol === "https:" && !url.username && !url.password ? url.href : undefined; } catch { return undefined; } }
async function api<T>(path: string, method = "GET", payload?: unknown, idempotencyKey?: string): Promise<T> {
  const response = await fetch(`/sub/api/${path}`, { method, credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-Pauk-Customer": "1", ...(idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {}) },
    body: method === "GET" ? undefined : JSON.stringify(payload || {}) });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Не удалось выполнить действие");
  return data;
}

export function CustomerPortal({ personalToken, onBack }: { personalToken?: string; onBack?: () => void }) {
  const [authMode, setAuthMode] = useState<"login" | "register">("register");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const emailMode = useRef(false);
  const portalApi = useCallback(<T,>(path: string, method = "GET", payload?: unknown, key?: string) => api<T>(emailMode.current && /^(overview|context|orders|payments\/|native\/|accounts\/|device-purchases\/)/.test(path) ? `email/${path}` : path, method, payload, key), []);
  const [personal, setPersonal] = useState<{ kind: string; account_id?: number; info: PublicSubscription; can_renew: boolean } | null>(null);
  const personalLoaded = useRef(false);
  const [currentProof, setCurrentProof] = useState(personalToken);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const busyLock = useRef(false);
  const [intent, setIntent] = useState<PurchaseIntent>("new");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("subscriptions");
  const [accountId, setAccountId] = useState(0);
  const [planId, setPlanId] = useState(0);
  const [gateway, setGateway] = useState("");
  const [challenge, setChallenge] = useState<{ id: string; deep_link?: string; code?: string } | null>(null);
  const [orders, setOrders] = useState<Order[]>([]);
  const [checkout, setCheckout] = useState<Order | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [referral, setReferral] = useState<Referral | null>(null);
  const [promo, setPromo] = useState("");
  const [shopName, setShopName] = useState("");
  const [setup, setSetup] = useState<{ key: string; title: string; app_name: string; download_url: string; instruction: string }[]>([]);
  const [tickets, setTickets] = useState<Ticket[]>([]);
  const [ticket, setTicket] = useState<Ticket | null>(null);
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [replyMessage, setReplyMessage] = useState("");
  const requests = useRef(new Map<string, string>());
  const purchases = useRef(new PurchaseRequests());
  useEffect(() => { window.scrollTo(0, 0); }, [tab]);

  const load = useCallback(async () => {
    const profile = await api<{ authenticated?: boolean; telegram?: unknown }>("profile");
    emailMode.current = !profile.telegram && !!profile.authenticated;
    const data = await portalApi<Overview>("overview");
    const gateways = [...data.gateways].sort((left, right) => (gatewayPriority[left.code] ?? 2) - (gatewayPriority[right.code] ?? 2));
    setOverview({ ...data, gateways }); setLoading(false);
    setPlanId(current => current || data.plans[0]?.id || 0);
    setGateway(current => gateways.some(row => row.code === current) ? current : gateways[0]?.code || "");
    if (currentProof) {
      const context = await portalApi<{ kind: string; account_id?: number; info: PublicSubscription; can_renew: boolean }>("context", "POST", { subscription_token: currentProof });
      setPersonal(context); if (!personalLoaded.current) setAccountId(context.kind === "native" ? -1 : context.account_id || 0);
      if (!personalLoaded.current) { setTab("plans"); setIntent("renew"); } personalLoaded.current = true;
    }
  }, [currentProof, portalApi]);
  useEffect(() => {
    let active = true;
    api<{ telegram?: unknown; authenticated?: boolean }>("profile").then(profile => {
      if (active && (profile.telegram || profile.authenticated)) return load();
    }).catch(err => { if (active && err instanceof Error && err.message !== "Войдите в личный кабинет") setError(err.message); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [load]);
  useEffect(() => {
    if (!challenge) return;
    let active = true;
    const timer = setInterval(async () => {
      try {
        const response = await portalApi<{ status: string }>(`telegram/poll/${challenge.id}`, "POST");
        if (!active) return;
        if (response.status === "LINKED") { setChallenge(null); await load(); }
        if (response.status === "EXPIRED") { setChallenge(null); setError("Время подтверждения истекло. Нажмите «Войти» ещё раз"); }
      } catch { if (active) { setChallenge(null); setError("Не удалось завершить вход. Попробуйте снова"); } }
    }, 4000);
    return () => { active = false; clearInterval(timer); };
  }, [challenge, load, portalApi]);

  async function action(work: () => Promise<void>) {
    if (busyLock.current) return;
    busyLock.current = true;
    setBusy(true); setError(""); setNotice("");
    try { await work(); } catch (err) { setError(err instanceof Error ? err.message : "Попробуйте ещё раз"); }
    finally { busyLock.current = false; setBusy(false); }
  }
  const refreshPayments = useCallback(async () => {
    const rows = (await portalApi<{ orders: Order[] }>("orders")).orders;
    purchases.current.observe(rows); setOrders(rows);
    let updated = rows.find(row => row.id === checkout?.id && row.kind === checkout?.kind);
    if (updated && pendingPayment(updated.status) && updated.kind !== "device") updated = (await portalApi<{ order: Order }>(`orders/${updated.id}/checkout`, "POST")).order;
    if (updated) {
      const latest = updated;
      setCheckout(current => current?.id === latest.id ? mergePayment(current, latest) : current);
      if (updated.status === "APPLIED" && checkout?.status !== "APPLIED") await load();
    }
  }, [portalApi, checkout?.id, checkout?.kind, checkout?.status, load]);
  useEffect(() => {
    if (tab !== "payments" || !checkout || !["PENDING", "PAYMENT_PENDING", "WAITING_PAYMENT", "PAYMENT_REVIEW", "PAID", "APPLY_FAILED"].includes(checkout.status)) return;
    const refresh = () => { if (document.visibilityState === "visible" && !busyLock.current) void refreshPayments().catch(() => {}); };
    const timer = window.setInterval(refresh, 15000);
    window.addEventListener("focus", refresh);
    return () => { window.clearInterval(timer); window.removeEventListener("focus", refresh); };
  }, [tab, checkout, refreshPayments]);
  async function openTab(next: Tab) {
    setTab(next); setError(""); setNotice("");
    await action(async () => {
      if (next === "payments") await refreshPayments();
      if (next === "bonuses" && overview?.features.affiliate) setReferral(await portalApi<Referral>("referral"));
      if (next === "support") { setTickets((await portalApi<{ tickets: Ticket[] }>("support/tickets")).tickets); setSetup((await portalApi<{ platforms: typeof setup }>("setup")).platforms); }
      if (next === "devices") { const target = accountId || allAccounts[0]?.id; if (target) { setAccountId(target); await deviceAction("list", undefined, target); } }
      if (next === "payments" || next === "subscriptions") await load();
    });
  }
  function chooseIntent(next: PurchaseIntent) {
    setIntent(next); setCheckout(null); setError(""); setNotice("");
    setAccountId(next === "new" ? 0 : accountId || allAccounts[0]?.id || 0);
    setTab("plans");
  }
  function renew(account: Account) { setIntent("renew"); setAccountId(account.id); setCheckout(null); setTab("plans"); }
  const nativeAccount: Account | null = personal?.kind === "native" ? { id: -1, name: personal.info.name, status: personal.info.status.toUpperCase(), expire_at: personal.info.expires_at || undefined, device_limit: personal.info.device_limit, traffic_limit_bytes: personal.info.limit_bytes, used_traffic_bytes: personal.info.used_bytes, can_renew: personal.can_renew } : null;
  const allAccounts = [...(nativeAccount ? [nativeAccount] : []), ...(overview?.subscriptions || [])].map(account => ({ ...account, name: subscriptionName(account) }));
  const selectedAccount = allAccounts.find(account => account.id === accountId);
  async function deviceAction(actionName: "list" | "remove" | "remove-all" | "rotate", device?: string, selected = accountId) {
    const requestIdentity = JSON.stringify(["device", currentProof, selected, actionName, device]);
    if (!requests.current.has(requestIdentity)) requests.current.set(requestIdentity, crypto.randomUUID());
    const requestKey = requests.current.get(requestIdentity)!;
    if (selected === -1 && currentProof) {
      const result = await portalApi<{ devices: Device[]; subscription_token?: string }>("native/devices", "POST", { subscription_token: currentProof, action: actionName, device_id: device, request_key: requestKey });
      setDevices(result.devices);
      if (result.subscription_token) {
        setCurrentProof(result.subscription_token);
        window.history.replaceState(null, "", `/sub/${result.subscription_token}`);
        setNotice("Новая ссылка сохранена в адресной строке. Скопируйте её в ваши VPN-приложения; старая ссылка больше не обновляет подписку.");
      }
    } else if (selected > 0) {
      if (actionName === "rotate") {
        await portalApi(`accounts/${selected}/revoke`, "POST", {}, requestKey); setDevices([]); await load();
        setNotice("Ссылка заменена. Откройте «Мои подписки», чтобы скопировать новую");
      } else setDevices((await portalApi<{ devices: Device[] }>(`accounts/${selected}/devices${actionName === "remove" ? `/${encodeURIComponent(device || "")}` : ""}`, actionName === "list" ? "GET" : "DELETE")).devices);
    }
    requests.current.delete(requestIdentity);
  }
  async function purchase() {
    if (intent === "device" || (intent === "renew" && !selectedAccount)) throw new Error("Выберите подписку для продления");
    // The previous payment may have completed in another tab while this one
    // still holds its pending request key. Refresh before deciding to reuse it.
    purchases.current.observe((await portalApi<{ orders: Order[] }>("orders")).orders);
    const targetId = intent === "new" ? 0 : accountId;
    const payload = { plan_id: planId, account_id: targetId > 0 ? targetId : null, gateway, ...(targetId === -1 ? { subscription_token: currentProof } : {}) };
    const key = JSON.stringify(payload);
    const result = await portalApi<{ order: Order }>("orders", "POST", { ...payload, request_key: purchases.current.keyFor(key) });
    purchases.current.received(key, result.order);
    setCheckout(result.order); setTab("payments");
    const rows = (await portalApi<{ orders: Order[] }>("orders")).orders;
    purchases.current.observe(rows);
    setOrders(rows);
    const updated = rows.find(row => row.id === result.order.id);
    if (updated) setCheckout(mergePayment(result.order, updated));
  }
  async function cancelPayment(order: Order) {
    if (busyLock.current) throw new Error("Дождитесь завершения предыдущего действия.");
    busyLock.current = true; setBusy(true); setError(""); setNotice("");
    try {
      const response = await portalApi<{ order: Order }>(`payments/${order.id}/cancel`, "POST", { kind: order.kind || "subscription", confirm_cancel: true });
      const updated = response.order;
      purchases.current.observe([updated]);
      setOrders(current => current.map(row => row.id === updated.id && row.kind === updated.kind ? mergePayment(row, updated) : row));
      setCheckout(current => current?.id === updated.id && current?.kind === updated.kind ? mergePayment(current, updated) : current);
      setNotice("Неоплаченный заказ отменён. Подписка не изменилась. Можно выбрать новый способ оплаты.");
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Не удалось отменить заказ. Проверьте его статус.");
      await refreshPayments().catch(() => {});
      throw failure;
    } finally { busyLock.current = false; setBusy(false); }
  }
  async function checkPayment(): Promise<boolean> {
    if (!checkout || busyLock.current) return false;
    busyLock.current = true; setBusy(true); setError("");
    try {
      const result = await portalApi<{ payable: boolean }>(`payments/${checkout.id}/check`, "POST");
      return result.payable === true;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось проверить заказ. Попробуйте позже.");
      await refreshPayments().catch(() => {});
      return false;
    } finally { busyLock.current = false; setBusy(false); }
  }
  async function upload(file?: File) {
    if (!file || !checkout) return;
    if (file.size > 2 * 1024 * 1024) throw new Error("Чек должен быть не больше 2 МБ");
    const encoded = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader(); reader.onerror = reject;
      reader.onload = () => resolve(String(reader.result).split(",")[1]); reader.readAsDataURL(file);
    });
    const result = await portalApi<{ order: Order; message: string }>(`orders/${checkout.id}/receipt`, "POST", { content: encoded });
    setCheckout(result.order); setNotice(result.message);
    setOrders((await portalApi<{ orders: Order[] }>("orders")).orders);
  }

  async function deleteSubscription(account: Account) {
    if (busyLock.current) throw new Error("Дождитесь завершения предыдущего действия.");
    busyLock.current = true; setBusy(true); setError(""); setNotice("");
    try {
      await portalApi(`accounts/${account.id}`, "DELETE", { confirm_delete: true });
      setOverview(current => current ? { ...current, subscriptions: current.subscriptions.filter(row => row.id !== account.id) } : current);
      if (accountId === account.id) { setAccountId(0); setDevices([]); }
      if (personal?.account_id === account.id) {
        setPersonal(null); setCurrentProof(undefined); personalLoaded.current = false;
        window.history.replaceState(null, "", "/sub/");
      }
      requests.current.clear(); purchases.current.clear();
      setNotice("Подписка удалена. История платежей сохранена.");
    } finally { busyLock.current = false; setBusy(false); }
  }

  async function buyExtraDevice() {
    if (!selectedAccount?.device_limit) throw new Error("Выберите подписку с ограниченным числом устройств");
    const target = selectedAccount.id;
    const identity = JSON.stringify(["extra-device", target, target === -1 ? currentProof : undefined]);
    purchases.current.observe((await portalApi<{ orders: Order[] }>("orders")).orders);
    const requestKey = purchases.current.keyFor(identity);
    const path = target === -1 ? "native/extra-device" : `accounts/${target}/extra-device`;
    const payload = target === -1 ? { subscription_token: currentProof, request_key: requestKey } : { request_key: requestKey };
    const response = await portalApi<Order>(path, "POST", payload, requestKey);
    const result = { ...response, kind: "device", plan: response.plan || "Дополнительное устройство", status: response.status || "WAITING_PAYMENT" };
    purchases.current.received(identity, result);
    setCheckout(result); setTab("payments");
    const rows = (await portalApi<{ orders: Order[] }>("orders")).orders;
    purchases.current.observe(rows); setOrders(rows);
    const updated = rows.find(row => row.id === result.id && row.kind === "device");
    if (updated) setCheckout(mergePayment(result, updated));
  }

  return <div className="customer-backdrop"><div className="subscription-shell customer-shell pauk-commerce">
    <header className="subscription-header"><Link href="/sub/" className="subscription-brand"><span className="subscription-logo"><img src="/pauk-emblem.png" alt="Эмблема PAUK" width={46} height={46} /></span><strong>PAUK</strong><span className="subscription-divider" /><span className="subscription-header-label">Личный кабинет</span></Link><div className="customer-header-actions"><span className="customer-brand-motto">СВОБОДА ВСЕГДА РЯДОМ</span>{overview && <button className="customer-text-button" disabled={busy} onClick={() => action(async () => { await portalApi("logout", "POST"); setOverview(null); setCheckout(null); setOrders([]); setDevices([]); setReferral(null); setTicket(null); setTickets([]); requests.current.clear(); purchases.current.clear(); setIntent("new"); setAccountId(0); setPersonal(null); personalLoaded.current = false; })}>Выйти</button>}</div></header>
    <main id="main-content">{onBack && <button className="customer-text-button" onClick={onBack}>← К моей подписке</button>}
      {!overview ? <section className="customer-welcome"><div className="customer-welcome-copy"><img className="commerce-welcome-emblem" src="/pauk-emblem.png" alt="Эмблема PAUK" width={184} height={184} /><p className="subscription-kicker">ВАШ VPN. ВАШ КАБИНЕТ.</p><h1>Свобода всегда<br /><em>рядом.</em></h1><p>Продлевайте подписку, подключайте устройства и следите за платежами в одном месте.</p><div className="customer-welcome-tags"><span>Оплата в панели PAUK</span><span>Подписки и устройства</span></div></div><div className="customer-login-card"><span className="customer-icon-large">↗</span><h2>{authMode === "register" ? "Начните с PAUK" : "С возвращением"}</h2><p>Покупайте и продлевайте VPN прямо на сайте. Telegram не требуется.</p>
          {loading ? <p role="status">Загружаем кабинет…</p> : <>
            <div className="customer-auth-tabs" role="group" aria-label="Вход или регистрация"><button type="button" aria-pressed={authMode === "register"} onClick={() => { setAuthMode("register"); setError(""); }}>Создать аккаунт</button><button type="button" aria-pressed={authMode === "login"} onClick={() => { setAuthMode("login"); setError(""); }}>Войти</button></div>
            <form onSubmit={e => { e.preventDefault(); void action(async () => {
              if (authMode === "register") await api("session", "POST");
              await api(authMode, "POST", { email, password, ...(authMode === "register" ? { display_name: displayName } : {}) });
              setPassword(""); setChallenge(null); await load();
            }); }}>
              {authMode === "register" && <label className="customer-field">Как к вам обращаться<input name="name" autoComplete="name" maxLength={96} value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="Ваше имя" /></label>}
              <label className="customer-field">Email<input name="email" type="email" autoComplete="username" required maxLength={254} value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" /></label>
              <label className="customer-field">Пароль<input name="password" type="password" autoComplete={authMode === "register" ? "new-password" : "current-password"} required minLength={authMode === "register" ? 8 : 1} maxLength={256} value={password} onChange={e => setPassword(e.target.value)} placeholder={authMode === "register" ? "Не менее 8 символов" : "Ваш пароль"} /></label>
              <button className="customer-button primary" disabled={busy}>{busy ? "Подождите…" : authMode === "register" ? "Создать аккаунт →" : "Войти →"}</button>
              {authMode === "register" && <p className="customer-note">Сохраните пароль: по нему вы сможете открыть подписку на другом устройстве.</p>}
            </form>
            <div className="customer-login-divider" /><p className="customer-note">Пользовались ботом? Можно войти в прежний аккаунт.</p>
            {challenge ? <><a className="customer-button" href={safeLink(challenge.deep_link)} target="_blank" rel="noopener noreferrer">Подтвердить в Telegram ↗</a><p className="customer-note" role="status">Подтвердите вход в боте и вернитесь сюда.</p><button className="customer-text-button" onClick={() => setChallenge(null)}>Отмена</button></> : <button className="customer-button" disabled={busy} onClick={() => action(async () => { await api("session", "POST"); setChallenge(await api("telegram/challenge", "POST")); })}>Войти через Telegram</button>}
          </>}<div className="customer-login-divider" /><p className="customer-note">Уже есть персональная ссылка? Откройте её, чтобы посмотреть срок подписки и добавить VPN в приложение.</p></div></section> : <>
        {tab !== "plans" && tab !== "payments" && <div className="customer-heading"><div><p className="subscription-kicker">ЛИЧНОЕ ПРОСТРАНСТВО</p><h1>Здравствуйте, {overview.profile.name}</h1><p>Подписка, оплата и устройства — всё под рукой.</p></div><button className="customer-button" disabled={busy} onClick={() => action(load)}>↻ Обновить</button></div>}
        <nav className={`customer-tabs ${tab === "plans" || tab === "payments" ? "commerce-top-nav" : ""}`} aria-label="Разделы кабинета">{tabs.filter(item => overview.profile.mode !== "email" || item.id !== "bonuses").map(item => <button key={item.id} aria-current={tab === item.id ? "page" : undefined} disabled={busy} onClick={() => void openTab(item.id)}><span aria-hidden="true">{item.icon}</span>{item.label}</button>)}</nav>
        {tab === "subscriptions" && <section><div className="customer-section-title"><div><h2>Мои подписки</h2><p>Одно пространство для всех ваших подключений.</p></div><button className="customer-button primary" onClick={() => { chooseIntent("new"); }}>+ Новая подписка</button></div><div className="customer-account-grid">{allAccounts.map(account => <article className="customer-card account" key={account.id}><div className="customer-card-top"><span className="customer-icon-large">◈</span><span className={`customer-badge ${account.status === "ACTIVE" ? "positive" : ""}`}>{statusLabel(account.status)}</span></div><h3>{account.name}</h3><p>{subscriptionExpiry(account)}</p><div className="customer-account-facts"><div><span>Устройства</span><strong>{account.device_limit === 0 ? "Без лимита" : account.device_limit ?? "—"}</strong></div><div><span>Трафик</span><strong>{account.unavailable ? "—" : account.traffic_limit_bytes ? trafficLabel(account.traffic_limit_bytes) : "Безлимит"}</strong></div></div><div className="customer-actions"><button className="customer-button primary" onClick={() => renew(account)} disabled={busy || account.delete_pending || account.unavailable || account.can_renew === false}>Продлить →</button>{!account.delete_pending && safeLink(account.subscription_url) && <a className="customer-button" href={safeLink(account.subscription_url)}>Подключить</a>}</div>{account.can_delete && <CustomerSubscriptionDelete name={account.name} disabled={busy} pending={account.delete_pending} onDelete={() => deleteSubscription(account)} />}</article>)}</div>{!allAccounts.length && <div className="customer-empty"><h3>Ваше первое подключение</h3><p>Выберите подходящий тариф — подписка появится здесь после оплаты.</p>{overview.features.trial && <button className="customer-button primary" disabled={busy} onClick={() => action(async () => { await portalApi("trial", "POST"); await load(); setNotice("Пробная подписка готова"); })}>Попробовать {overview.features.trial_days} дня</button>}</div>}</section>}
        {tab === "plans" && <PlanCheckout intent={intent} onIntent={chooseIntent} accounts={allAccounts} accountId={intent === "new" ? 0 : accountId} onAccount={setAccountId} plans={overview.plans} planId={planId} onPlan={setPlanId} gateways={overview.gateways} gateway={gateway} onGateway={setGateway} features={overview.features} timeOnly={overview.profile.mode === "email" || accountId === -1} canRenew={!!selectedAccount && selectedAccount.can_renew !== false && !selectedAccount.unavailable && !selectedAccount.delete_pending} busy={busy} onPurchase={() => void action(purchase)} onDevice={() => void action(buyExtraDevice)} />}
        {tab === "payments" && <section className="commerce-payments-page"><div className="customer-section-title"><div><h1>Платежи</h1><p>Все ваши заказы и статусы оплаты.</p></div>{!checkout && <button className="customer-button" disabled={busy} onClick={() => void openTab("payments")}>↻ Обновить</button>}</div>{checkout && <PaymentDetails order={checkout} busy={busy} onUpload={file => void action(() => upload(file))} onSubscriptions={() => void openTab("subscriptions")} onDevices={() => void openTab("devices")} onSupport={() => void openTab("support")} onRefresh={() => void action(refreshPayments)} onBeforePay={checkPayment} onCancel={() => cancelPayment(checkout)} />}<h3 className="commerce-history-title">История заказов</h3><div className="customer-history">{orders.map(order => <article className="customer-history-row" key={`${order.kind}:${order.id}`}><span className="customer-history-icon">{order.kind === "device" ? "▣" : "↗"}</span><div><strong>{orderPurpose(order)}{order.plan && order.kind !== "device" ? ` · ${order.plan}` : ""}</strong><small>{date(order.created_at)} · {order.payment_method === "TELEGRAM_STARS" ? "Telegram Stars" : order.payment_method === "MANUAL_RUB" ? "СБП / перевод" : "ЮMoney"}</small></div><span className={`customer-badge ${order.status === "APPLIED" ? "positive" : ""}`}>{statusLabel(order.status)}</span><strong>{money(order.amount, order.currency)}</strong><div className="customer-history-actions">{order.kind === "device" && ["PAID", "APPLY_FAILED"].includes(order.status) && <button className="customer-text-button" disabled={busy} onClick={() => action(async () => { await portalApi(`device-purchases/${order.id}/retry`, "POST"); const rows = (await portalApi<{ orders: Order[] }>("orders")).orders; setOrders(rows); const updated = rows.find(row => row.id === order.id); if (updated) setCheckout(current => current?.id === order.id ? { ...current, ...updated } : current); setNotice("Активация дополнительного устройства проверена"); })}>Повторить активацию →</button>}{order.can_cancel && (checkout?.id !== order.id || checkout?.kind !== order.kind) && <CustomerPaymentCancel title={`${orderPurpose(order)} · ${money(order.amount, order.currency)}`} disabled={busy} onCancel={() => cancelPayment(order)} />}{(!order.kind || order.kind === "subscription" || overview.profile.mode === "email" && order.kind === "web") && ["PENDING", "PAYMENT_PENDING", "WAITING_PAYMENT", "PAID", "APPLY_FAILED"].includes(order.status) && <button className="customer-text-button" disabled={busy} onClick={() => action(async () => setCheckout((await portalApi<{ order: Order }>(`orders/${order.id}/checkout`, "POST")).order))}>{["PAID", "APPLY_FAILED"].includes(order.status) ? "Повторить активацию →" : "Оплатить →"}</button>}</div></article>)}</div>{!orders.length && <div className="customer-empty"><h3>Платежей пока нет</h3><p>Здесь появится каждый ваш заказ и его статус.</p></div>}</section>}
        {tab === "devices" && <section><div className="customer-section-title"><div><h2>Ваши устройства</h2><p>Освобождайте слоты для новых телефонов и компьютеров.</p></div></div><label className="customer-field">Подписка<select disabled={busy} value={accountId} onChange={e => { const id = Number(e.target.value); setAccountId(id); setDevices([]); if (id) void action(() => deviceAction("list", undefined, id)); }}><option value={0}>Выберите подписку</option>{allAccounts.map(account => <option value={account.id} key={account.id}>{account.name}</option>)}</select></label>{selectedAccount && <><div className="customer-section-title"><span>{devices.length} привязанных · лимит {selectedAccount.unavailable ? "уточняется" : selectedAccount.device_limit === 0 ? "без ограничений" : selectedAccount.device_limit ?? "уточняется"}</span>{overview.features.extra_device && selectedAccount.device_limit !== 0 && <button className="customer-button" disabled={busy || selectedAccount.unavailable || selectedAccount.delete_pending || selectedAccount.can_add_device === false} onClick={() => chooseIntent("device")}>+ Добавить устройство · {money(overview.features.extra_device_rub)}</button>}</div><div className="customer-history">{devices.map((device, index) => <article className="customer-history-row" key={device.hwid || index}><span className="customer-history-icon">▣</span><div><strong>{device.deviceModel || device.platform || `Устройство ${index + 1}`}</strong><small>{device.platform} {device.osVersion}</small></div>{overview.features.devices && <button className="customer-text-button danger" disabled={busy} onClick={() => { if (confirm("Удалить привязку этого устройства? Оно сможет занять свободный слот при следующем обновлении подписки.")) void action(() => deviceAction("remove", device.hwid)); }}>Удалить</button>}</article>)}</div>{!devices.length && <p className="customer-empty">Устройства ещё не привязаны. Обновите подписку в VPN-приложении.</p>}<div className="customer-card customer-security"><h3>Безопасность подписки</h3><p>Если ссылка попала к посторонним, замените её. Старую ссылку потребуется обновить на ваших устройствах.</p><div className="customer-actions">{overview.features.devices && <button className="customer-button" disabled={busy || !devices.length} onClick={() => { if (confirm("Удалить все привязанные устройства?")) void action(() => deviceAction("remove-all")); }}>Удалить все устройства</button>}{overview.features.revoke && <button className="customer-button" disabled={busy} onClick={() => { if (confirm("Заменить ссылку подписки? Старая ссылка перестанет работать, привязки устройств будут удалены.")) void action(() => deviceAction("rotate")); }}>Заменить ссылку</button>}</div></div></>}</section>}
        {tab === "bonuses" && <section><div className="customer-section-title"><div><h2>Больше возможностей</h2><p>Промокоды и бонусы вашего аккаунта.</p></div></div><div className="customer-card"><h3>Есть промокод?</h3><form className="customer-inline-form" onSubmit={e => { e.preventDefault(); void action(async () => { setNotice((await portalApi<{ message: string }>("promo", "POST", { code: promo })).message); setPromo(""); await load(); }); }}><input aria-label="Промокод" value={promo} onChange={e => setPromo(e.target.value)} placeholder="Введите промокод" maxLength={64} required /><button className="customer-button primary" disabled={busy}>Применить</button></form></div>{referral && overview.features.affiliate && <div className="customer-referral"><article className="customer-card"><p className="subscription-kicker">ПРИГЛАШАЙТЕ ДРУЗЕЙ</p><h3>{referral.share_bps / 100}% от чистой суммы покупок</h3><p>Комиссия сервиса — {referral.fee_bps / 100}%. Начисления доступны через {referral.hold_days} дней.</p><label className="customer-field">Ваша ссылка<input readOnly value={referral.link} onFocus={e => e.currentTarget.select()} /></label><button className="customer-button" onClick={() => action(async () => { await navigator.clipboard.writeText(referral.link); setNotice("Партнёрская ссылка скопирована"); })}>Скопировать ссылку</button><p className="customer-note">Приглашено: {referral.invited}</p></article><article className="customer-card"><h3>Ваши начисления</h3>{referral.balances.map(balance => <div className="customer-balance" key={balance.currency}><div><strong>{money(balance.available_minor / balance.minor_scale, balance.currency)}</strong><small>Доступно · ожидают {money(balance.hold_minor / balance.minor_scale, balance.currency)}</small></div><button className="customer-button" disabled={busy || balance.available_minor <= 0} onClick={() => action(async () => { setNotice((await portalApi<{ message: string }>("referral/withdraw", "POST", { currency: balance.currency })).message); setReferral(await portalApi("referral")); })}>Вывести</button></div>)}{referral.pending_days > 0 && <button className="customer-button" disabled={busy} onClick={() => action(async () => { setNotice((await portalApi<{ message: string }>("referral/claim", "POST")).message); setReferral(await portalApi("referral")); })}>Забрать бонусные дни</button>}{referral.withdrawals.map(row => <p className="customer-note" key={row.id}>{money(row.amount_minor / row.scale, row.currency)} · {statusLabel(row.status)}</p>)}</article><article className="customer-card"><h3>Ваш магазин</h3><p>{referral.shop ? `${referral.shop.name} · ${statusLabel(referral.shop.status)}` : "Укажите своё название для подписок приглашённых клиентов"}</p><form className="customer-inline-form" onSubmit={e => { e.preventDefault(); void action(async () => { await portalApi("referral/shop", "POST", { name: shopName }); setReferral(await portalApi("referral")); setNotice("Название отправлено на проверку"); }); }}><input aria-label="Название магазина" value={shopName} onChange={e => setShopName(e.target.value)} minLength={2} maxLength={64} placeholder="Название магазина" required /><button className="customer-button" disabled={busy}>Отправить</button></form><p className="customer-note">Новое название включится после одобрения администратором.</p></article></div>}</section>}
        {tab === "support" && <section><div className="customer-section-title"><div><h2>Всегда на связи</h2><p>Вопросы об оплате, подписке или подключении.</p></div></div><div className="customer-account-grid">{setup.map(platform => <details className="customer-card" key={platform.key}><summary>{platform.title} · {platform.app_name}</summary><p style={{whiteSpace:"pre-wrap"}}>{platform.instruction}</p>{safeLink(platform.download_url) && <a className="customer-button" href={safeLink(platform.download_url)} target="_blank" rel="noopener noreferrer">Скачать приложение ↗</a>}</details>)}</div><div className="customer-support-grid"><article className="customer-card"><h3>Написать в поддержку</h3><form onSubmit={e => { e.preventDefault(); void action(async () => { await portalApi("support/tickets", "POST", { subject, message, category: "OTHER" }); setSubject(""); setMessage(""); setTickets((await portalApi<{ tickets: Ticket[] }>("support/tickets")).tickets); setNotice("Обращение отправлено"); }); }}><label className="customer-field">Тема<input required minLength={3} maxLength={160} value={subject} onChange={e => setSubject(e.target.value)} placeholder="Чем можем помочь?" /></label><label className="customer-field">Сообщение<textarea required minLength={2} maxLength={4000} value={message} onChange={e => setMessage(e.target.value)} placeholder="Расскажите, что произошло" /></label><button className="customer-button primary" disabled={busy}>Отправить обращение →</button></form></article><article className="customer-card"><h3>Мои обращения</h3>{tickets.map(row => <button key={row.id} className="customer-ticket-button" onClick={() => action(async () => { setTicket((await portalApi<{ ticket: Ticket }>(`support/tickets/${row.id}`)).ticket); setReplyMessage(""); })}><strong>{row.subject}</strong><small>{statusLabel(row.status)} →</small></button>)}{!tickets.length && <p>Обращений пока нет.</p>}{ticket && <div className="customer-conversation"><h4>{ticket.subject}</h4>{ticket.messages?.map((item, index) => <p key={index} className={item.sender === "USER" ? "from-user" : "from-support"}><small>{item.sender === "USER" ? "Вы" : "Поддержка"}</small>{item.text}</p>)}{ticket.status !== "CLOSED" && <form onSubmit={e => { e.preventDefault(); void action(async () => { await portalApi(`support/tickets/${ticket.id}/messages`, "POST", { message: replyMessage }); setTicket((await portalApi<{ ticket: Ticket }>(`support/tickets/${ticket.id}`)).ticket); setReplyMessage(""); }); }}><label className="customer-field">Ответ<textarea minLength={2} maxLength={4000} required value={replyMessage} onChange={e => setReplyMessage(e.target.value)} /></label><button className="customer-button" disabled={busy}>Отправить</button></form>}</div>}</article></div></section>}
      </>}
      {error && <div className="customer-feedback error" role="alert">{error}</div>}
      {notice && <div className="customer-feedback" role="status">{notice}</div>}
    </main><footer className="subscription-footer"><span>Ваше подключение. Ваше пространство.</span><span>Работает на PAUK</span></footer>
  </div></div>;
}
