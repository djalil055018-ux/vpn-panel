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
      <aside className="subscription-migration" aria-labelledby="subscription-migration-title">
        <h2 id="subscription-migration-title">Обновите ссылку подписки PAUK</h2>
        <p>Если в приложении сохранён старый адрес, скопируйте свою ссылку с sub.pauk.click на этой странице или откройте подписку в <a href="https://t.me/paauuk_bot">боте PAUK</a>.</p>
        <p>Добавьте новую ссылку в VPN-приложение, обновите подписку и проверьте подключение. Затем удалите старую запись из приложения. Срок действия подписки сохраняется.</p>
      </aside>
      {children}
    </>
  );
}


