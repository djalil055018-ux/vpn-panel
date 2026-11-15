import { redirect } from "next/navigation";
import { requireSession } from "@/lib/auth";
import { getProtocolTemplates } from "@/lib/control-plane";
import { ProtocolTemplateLibrary } from "@/components/protocol-template-library";
import "@/app/protocol-templates.css";
export const dynamic = "force-dynamic";
export default async function ProtocolTemplatesPage({searchParams}:{searchParams:Promise<{template?:string;installation?:string}>}) {
  const session = await requireSession();
  if (session.role === "monitor") redirect("/monitor");
  const [catalog,query] = await Promise.all([getProtocolTemplates(),searchParams]);
  return <><header className="page-header"><div><div className="eyebrow">Инфраструктура</div><h1>Шаблоны протоколов</h1><p>Выберите шаблон, проверьте параметры и добавьте сервис на сервер.</p></div><div className="header-count">{catalog.templates.filter(t => !t.legacy).length}</div></header><ProtocolTemplateLibrary catalog={catalog} canApply={session.role==="owner"} initialTemplate={query.template} initialInstallation={query.installation}/></>;
}
