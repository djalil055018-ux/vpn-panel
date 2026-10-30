export type MonitoringIncident = { id: string; rule: string; resource: string; resource_name: string; severity: "warning" | "critical"; observed_since: string; last_observed_at: string; opened_at: string; resolved_at: string | null; acknowledged_at: string | null };
export type MonitoringStatus = { generated_at: string; last_success_at: string | null; open_count: number; critical_count: number; incidents: MonitoringIncident[] };
export type WebhookQueueStatus = { generated_at: string; last_dispatch_at: string | null; enabled_endpoints: number; pending_deliveries: number; overdue_deliveries: number; failed_deliveries: number };
export const incidentRules: Record<string, { title: string; help: string; href: string }> = {
  traffic_delivery_delayed: { title: "Учёт трафика задерживается", help: "Нода в сети, но свежие измерения трафика не подтверждаются. Проверьте агент и очередь доставки на ноде.", href: "/operations" },
  webhook_worker_stale: { title: "Доставка webhooks не проверяется", help: "Нет успешного запуска службы более 90 секунд. Проверьте службу доставки.", href: "/webhooks" },
  webhook_queue_stalled: { title: "Очередь webhooks задерживается", help: "Срок очередной попытки прошёл более трёх минут назад; задержка сохраняется две минуты. Проверьте службу доставки и получателей.", href: "/webhooks" },
  webhook_delivery_failed: { title: "Webhook не доставлен", help: "Все автоматические попытки исчерпаны. Проверьте получателя и повторите доставку вручную.", href: "/webhooks" },
  node_offline: { title: "Нет связи с нодой", help: "Проверьте доступность сервера и работу агента.", href: "/nodes" },
  node_unhealthy: { title: "Нода сообщает о проблеме", help: "Откройте управление нодой и проверьте состояние ядра.", href: "/nodes" },
  node_not_converged: { title: "Обновление доступа задерживается", help: "Поколения не совпадают более пяти минут. Проверьте развёртывание.", href: "/deployments" },
  backup_missing: { title: "Нет проверенной резервной копии", help: "Проверьте расписание и результат резервного копирования.", href: "/operations" },
  backup_failed: { title: "Ошибка резервного копирования", help: "Проверьте службу копирования, место на диске и последнюю успешную копию.", href: "/operations" },
  backup_stale: { title: "Резервная копия устарела", help: "Последняя успешная или проверенная копия старше 36 часов.", href: "/operations" },
  backup_report_stale: { title: "Отчёт о копировании не поступает", help: "Нода не присылала отчёт более двух часов либо ещё не присылала его.", href: "/operations" },
  disk_low: { title: "Мало свободного места", help: "По последнему доступному измерению осталось менее 1 ГБ.", href: "/operations" },
  disk_unknown: { title: "Не удалось проверить свободное место", help: "Проверьте доступ службы мониторинга к каталогу платформы.", href: "/operations" },
  certificate_expired: { title: "Сертификат истёк", help: "Проверьте выпуск и применение действующего сертификата.", href: "/certificates" },
  certificate_failed: { title: "Ошибка выпуска сертификата", help: "Проверьте последнее задание сертификата и настройки домена.", href: "/certificates" },
  certificate_expiring: { title: "Сертификат скоро истекает", help: "До окончания осталось не более 30 дней. Проверьте автоматическое продление.", href: "/certificates" },
  access_revocation_pending: { title: "Снятие доступа задерживается", help: "Неактивный доступ остаётся в желаемом состоянии более двух минут. Проверьте службу контроля доступа.", href: "/operations" },
};
