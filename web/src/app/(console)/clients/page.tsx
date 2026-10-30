import { ClientListUnavailable } from "@/components/client-list-unavailable";
import { supportsClientProvisioning } from "@/lib/node-runtime";
import { requireSession } from "@/lib/auth";
import {
  ClientManagement,
  type ClientServiceOption,
} from "@/components/client-management";

import {
  getNodes,
  getTenants,
  getVPNClients,
  getVPNClientDirectServiceIDs,
  getVPNClientUsage,
  getVPNServices,
  getAccessPlans,
  getAccessPlan,
} from "@/lib/control-plane";
import { categoriesForProtocols } from "@/lib/device-categories";

export const dynamic =
  "force-dynamic";

export default async function ClientsPage() {
  const session = await requireSession();
  const [
    tenants,
    nodes,
  ] =
    await Promise.all([
      getTenants(),
      getNodes(),
    ]);

  const clientsByTenant =
    await Promise.all(
      tenants.map(
        async (tenant) => {
          try {
            return await getVPNClients(
              tenant.id
            );
          } catch {
            return null;
          }
        }
      )
    );

  if (clientsByTenant.some(clients => clients === null)) return <ClientListUnavailable />;

  const plansByTenant =
    await Promise.all(
      tenants.map(
        async (tenant) => {
          try {
            return await getAccessPlans(
              tenant.id
            );
          } catch {
            return [];
          }
        }
      )
    );

  const accessPlans =
    plansByTenant
      .flat()
      .filter(
        (plan) =>
          plan.enabled
      );

  const servicesByNode =
    await Promise.all(
      nodes.map(
        async (node) => {
          try {
            return await getVPNServices(
              node.id
            );
          } catch {
            return [];
          }
        }
      )
    );

  const clients =
    clientsByTenant.flatMap(clients => clients ?? []);

  const usages = await Promise.all(
    clients.map(async (client) => {
      try {
        return await getVPNClientUsage(client.id);
      } catch {
        return null;
      }
    })
  );

  const directServiceIDs =
    await Promise.all(
      clients.map(
        async (client) => {
          try {
            return await getVPNClientDirectServiceIDs(
              client.id
            );
          } catch {
            return null;
          }
        }
      )
    );

  const serviceCatalog =
    new Map<
      string,
      ClientServiceOption
    >();

  servicesByNode.forEach(
    (
      nodeServices,
      index
    ) => {
      const node =
        nodes[index];

      nodeServices.forEach(
        (service) => {
          serviceCatalog.set(
            service.id,
            {
              id:
                service.id,
              label:
                `${node.name} · ${service.name}` +
                ` · ${service.protocol.toUpperCase()}` +
                ` · ${service.transport.toUpperCase()}` +
                ` · ${service.security.toUpperCase()}`,
            }
          );
        }
      );
    }
  );

  const directServices:
    Record<
      string,
      ClientServiceOption[] | null
    > = {};

  clients.forEach(
    (
      client,
      index
    ) => {
      const ids = directServiceIDs[index];
      directServices[client.id] = ids == null
        ? null
        : ids.map(
          (serviceID) =>
            serviceCatalog.get(
              serviceID
            ) ?? {
              id:
                serviceID,
              label:
                `VPN-сервис ${serviceID}`,
            }
        );
    }
  );

  const accessPlanDetails = await Promise.all(
    accessPlans.map(plan => getAccessPlan(plan.id).catch(() => null))
  );
  const assignedServiceIDs = new Map<string, Set<string>>(
    clients.map(client => [client.id, new Set<string>()])
  );
  clients.forEach((client, index) => {
    for (const serviceID of directServiceIDs[index] ?? []) {
      assignedServiceIDs.get(client.id)?.add(serviceID);
    }
  });
  for (const plan of accessPlanDetails) {
    if (!plan) continue;
    for (const clientID of plan.client_ids) {
      const assigned = assignedServiceIDs.get(clientID);
      if (!assigned) continue;
      for (const serviceID of plan.service_ids) assigned.add(serviceID);
    }
  }
  const protocolByServiceID = new Map(
    servicesByNode.flatMap(nodeServices => nodeServices.map(service => [service.id, service.protocol] as const))
  );
  const clientCategories = Object.fromEntries(
    clients.map(client => [
      client.id,
      categoriesForProtocols(
        [...(assignedServiceIDs.get(client.id) ?? [])]
          .map(serviceID => protocolByServiceID.get(serviceID) ?? "")
      ),
    ])
  );

  const services:
    ClientServiceOption[] =
    servicesByNode.flatMap(
      (
        nodeServices,
        index
      ) => {
        const node =
          nodes[index];

        return nodeServices
          .filter(service => service.enabled && supportsClientProvisioning(service))
          .map(
            (service) => ({
              id:
                service.id,
              label:
                `${node.name} · ${service.name}` +
                (
                  service.public_address &&
                  service.public_port
                    ? ` · ${service.public_address}:${service.public_port}`
                    : ""
                ),
            })
          );
      }
    );

  return (
    <>
      <header className="page-header">
        <div>
          <div className="eyebrow">
            РАБОЧЕЕ ПРОСТРАНСТВО
          </div>

          <h1>
            Клиенты
          </h1>

          <p>
            Доступ, подписки и использование вашей VPN-сети в одном месте.
          </p>
        </div>

      </header>

      <ClientManagement
        canDeleteImported={session.role === "owner"}
        connectionRevision={crypto.randomUUID()}
        tenants={tenants}
        accessPlans={accessPlans}
        clients={clients}
        usages={usages}
        services={services}
        directServices={
          directServices
        }
        clientCategories={clientCategories}
      />
    </>
  );
}
