import { requireSession } from "@/lib/auth";
import { getCertificateJobs, getNodeCertificates, getNodes } from "@/lib/control-plane";
import { CertificateManagement, type CertificateCard } from "@/components/certificate-management";
export const dynamic = "force-dynamic";
function agentSupportsCertificateDelete(version?: string) {
  const parts = version?.split(".").map(Number);
  return !!parts && parts.length === 3 && parts.every(Number.isInteger) && (parts[0] > 0 || parts[1] > 2 || (parts[1] === 2 && parts[2] >= 36));
}
export default async function CertificatesPage() {
  await requireSession();
  let data: { nodes: { id: string; name: string }[]; cards: CertificateCard[] };
  try {
    const nodes = await getNodes();
    const groups = await Promise.all(nodes.map(node => getNodeCertificates(node.id)));
    const cards: CertificateCard[] = await Promise.all(groups.flatMap((certs, index) => certs.map(async cert => ({
      id: cert.id, nodeName: nodes[index].name, domain: cert.domain, environment: cert.environment, status: cert.status,
      canDelete: agentSupportsCertificateDelete(nodes[index].agent_version),
      autoRenew: cert.auto_renew, issuer: cert.issuer, fingerprint: cert.fingerprint_sha256, expires: cert.not_after, error: !!cert.last_error,
      jobs: (await getCertificateJobs(cert.id)).map(job => ({ id: job.id, operation: job.operation, status: job.status, created_at: job.created_at })),
    }))));
    cards.sort((a, b) => Number(a.status === "revoked") - Number(b.status === "revoked") || a.domain.localeCompare(b.domain));
    data = { nodes: nodes.map(node => ({ id: node.id, name: node.name })), cards };
  } catch {
    return <><h1>Сертификаты</h1><div className="alert error">Не удалось загрузить сертификаты. Проверьте доступность контура управления и обновите страницу.</div></>;
  }
  return <><header className="page-header"><div><div className="eyebrow">СЕРТИФИКАТЫ И КЛЮЧИ</div><h1>Сертификаты</h1><p>Выпуск, продление и защищённое хранение ключей на нодах.</p></div><div className="header-count">{data.cards.filter(c => c.status !== "revoked").length}</div></header><CertificateManagement nodes={data.nodes} certificates={data.cards} /></>;
}
