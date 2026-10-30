import Link from "next/link";
import { installationOrigin } from "@/lib/installation-origin";
import type { NodeRuntime } from "@/lib/node-runtime";

import {
  AddNodeForm,
} from "@/components/add-node-form";

import {
  getTenants,
} from "@/lib/control-plane";

export const dynamic =
  "force-dynamic";

export default async function NewNodePage({searchParams}:{searchParams:Promise<{runtime?:string | string[]}>}) {
  const query = await searchParams;
  const requested = typeof query.runtime === "string" ? query.runtime : "";
  const defaultRuntime: NodeRuntime = requested === "amneziawg" || requested === "pptp" || requested === "wireguard" || requested === "hysteria2" || requested === "openvpn" ? requested : "xray";
  const tenantRecords =
    await getTenants();

  const tenants =
    tenantRecords.map(
      (tenant) => ({
        id: tenant.id,
        label: tenant.name,
      })
    );

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            ИНФРАСТРУКТУРА
          </div>

          <h1>
            Добавить сервер
          </h1>

          <p>
            Создайте запись, выполните команду на сервере — панель проверит подключение.
          </p>
        </div>

        <Link
          href="/nodes"
          className="button"
        >
          Все серверы
        </Link>
      </header>

      <AddNodeForm
        installationOrigin={installationOrigin(process.env.VPN_PLATFORM_PUBLIC_URL)}
        tenants={tenants}
        defaultRuntime={defaultRuntime}
      />
    </>
  );
}
