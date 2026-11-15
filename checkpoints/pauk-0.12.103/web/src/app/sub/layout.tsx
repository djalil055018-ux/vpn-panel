import type { Metadata } from "next";
import "./subscription.css";
import "./customer.css";
import "./commerce.css";
export const metadata: Metadata = {
  title: "Моя подписка · PAUK", description: "Подписка, устройства и подключение VPN",
  robots: { index: false, follow: false, nocache: true }, referrer: "no-referrer",
};

export default function SubscriptionLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      {process.env.PAUK_SUBSCRIPTION_MIGRATION_NOTICE?.trim() && (
        <aside className="subscription-migration" aria-labelledby="subscription-migration-title">
          <h2 id="subscription-migration-title">Обновление ссылки подписки</h2>
          <p>{process.env.PAUK_SUBSCRIPTION_MIGRATION_NOTICE.trim()}</p>
        </aside>
      )}
      {children}
    </>
  );
}


