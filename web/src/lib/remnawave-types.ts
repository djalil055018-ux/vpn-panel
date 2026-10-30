export type RemnawaveImport = {
  id: string;
  tenant_id: string;
  state: "held";
  created_at: string;
  report: {
    sha256: string;
    source_origin: string;
    contract_version: string;
    captured_at: string;
    users: number;
    devices: number;
    status_counts: Record<string, number>;
    reset_policy_counts: Record<string, number>;
    limited_users: number;
    hwid_limited_users: number;
    users_with_squads: number;
    subscription_urls: number;
    independent_trojan_credentials: number;
    independent_ss_credentials: number;
    cutover_ready: false;
    required_review: string[];
  };
};
export type RemnawaveImportClient = { source_user_id: number; source_status: string; client_id: string; name: string; held: boolean; deleted: boolean };
export const remnawaveReviewLabels: Record<string, string> = {
  source_delta_and_final_freeze: "Сверить изменения после снимка и согласовать момент переключения.",
  squads_nodes_hosts_to_target_services: "Сопоставить группы, ноды и адреса с сервисами новой панели.",
  protocol_credentials_and_endpoint_compatibility: "Проверить исходные ключи и пароли на целевых протоколах.",
  existing_subscription_urls_and_cutover: "Сохранить работу прежних ссылок подписки и проверить переключение.",
  quota_reset_policy_and_used_traffic: "Перенести использованный трафик и точные правила сброса лимита.",
  hwid_enforcement_and_registered_devices: "Проверить ограничения и список зарегистрированных устройств.",
};
export const remnawaveStatusLabels: Record<string,string> = { ACTIVE: "Активен", DISABLED: "Отключён", EXPIRED: "Срок истёк", LIMITED: "Лимит исчерпан" };
export const remnawaveResetLabels: Record<string,string> = { NO_RESET: "Без сброса", DAY: "Ежедневно", WEEK: "Еженедельно", MONTH: "Ежемесячно", MONTH_ROLLING: "Скользящий месяц" };
