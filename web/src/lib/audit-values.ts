export type AuditEventMetadata = { id: string; tenant_id: string | null; node_id: string | null; event_type: string; actor_type: string; actor_id: string | null; created_at: string; request_id?: string | null; request_outcome?: "responded" | "interrupted" | null; http_status?: number | null };
export type AuditHistory = { events: AuditEventMetadata[]; next_cursor: string };
export const auditActors: Record<string, string> = { admin: "Служебный доступ администратора", admin_account: "Персональный аккаунт", system: "Служба платформы", tenant_api_token: "Ключ владельца", integration: "Интеграция", agent: "Агент ноды", node: "Нода" };
const titles: Record<string, string> = {
  "admin_request.completed": "Результат административного запроса",
  "admin_mfa.enrollment_started": "Начата настройка двухфакторного входа", "admin_mfa.enabled": "Включён двухфакторный вход", "admin_mfa.disabled": "Отключён двухфакторный вход", "admin_mfa.recovery_used": "Использован резервный код", "admin_mfa.recovery_rotated": "Заменены резервные коды",
  "admin_session.revoked": "Завершён сеанс входа", "admin_session.all_revoked": "Завершены все сеансы аккаунта",
  "admin_request.started": "Запрошено административное действие", "admin_account.bootstrapped": "Инициализирован аккаунт владельца", "admin_account.created": "Создан аккаунт администратора", "admin_account.updated": "Изменён доступ администратора", "admin_account.password_changed": "Изменён пароль аккаунта", "admin_session.created": "Выполнен вход в панель",
  "billing.invoice_created": "Создан счёт", "billing.invoice_paid": "Подтверждена оплата", "billing.invoice_voided": "Аннулирован счёт", "billing.offer_created": "Создано предложение", "billing.offer_updated": "Изменено предложение",
  "access_plan.created": "Создан тариф", "access_plan.updated": "Изменён тариф", "access_plan.deleted": "Удалён тариф", "access_plan.service_attached": "Сервис добавлен в тариф", "access_plan.service_detached": "Сервис исключён из тарифа", "access_plan.client_attached": "Тариф назначен клиенту", "access_plan.client_detached": "Тариф снят с клиента",
  "vpn_client.updated": "Изменены настройки клиента", "vpn_access.inactive_reconciled": "Снят неактивный доступ", "tenant_api_token.created": "Выдан ключ владельца", "tenant_api_token.revoked": "Отозван ключ владельца", "tenant.branding_updated": "Изменено оформление кабинета",
  "webhook.endpoint_created": "Создан получатель событий", "webhook.endpoint_enabled_changed": "Изменено состояние доставки событий", "webhook.endpoint_deleted": "Удалён получатель событий", "webhook.delivery_retried": "Повторно запрошена доставка события", "monitoring.incident_acknowledged": "Инцидент отмечен администратором",
};
export function auditTitle(type: string) { return titles[type] ?? (type.includes("certificate") ? "Событие сертификата" : type.includes("deployment") ? "Событие развёртывания" : type.includes("recovery") ? "Событие восстановления" : type.startsWith("node") ? "Событие ноды" : "Событие платформы"); }

export function auditOutcome(event: AuditEventMetadata): string | null {
  if (event.request_outcome === "interrupted") return "Обработка прервана. Итог изменения не подтверждён.";
  if (event.request_outcome !== "responded" || event.http_status == null) return null;
  if (event.http_status === 202) return "Запрос принят в обработку";
  if (event.http_status < 300) return "Успешный ответ панели";
  if (event.http_status < 400) return "Перенаправление";
  if (event.http_status < 500) return "Запрос отклонён";
  return "Ошибка обработки запроса";
}
