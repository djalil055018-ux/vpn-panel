import { PortalLogin } from "@/components/portal-login";
export const dynamic = "force-dynamic";
export default function PortalLoginPage() { return <main className="portal-login"><section className="panel"><div className="panel-header"><div><div className="eyebrow">PAUK</div><h1>Кабинет владельца</h1><p>Войдите с ключом, выданным администратором для вашего владельца.</p></div></div><PortalLogin /><p className="portal-note">Права определяются ключом. Сеанс действует до 8 часов; отзыв ключа закрывает доступ к кабинету.</p></section></main>; }
