type Client = { id: string; name: string };

export function BotPlanMembers({ assigned = [], clients, className = "plan-members" }: {
  assigned?: string[];
  clients: Client[];
  className?: string;
}) {
  const ids = [...new Set(assigned)];
  if (ids.length === 0) return null;
  return <section className={className}>
    <h3>Клиенты бота <span className="plan-count">{ids.length}</span></h3>
    <p className="plan-muted">Назначения меняются вместе с подписками в боте. Ручные назначения действуют независимо.</p>
    <ul>{ids.map(id => <li key={id}><span>{clients.find(client => client.id === id)?.name ?? "Недоступная запись"}</span></li>)}</ul>
  </section>;
}
