import type { Lifecycle } from "@/lib/control-plane";

type OnboardingFacts = Pick<Lifecycle,
  "registered" | "online" | "health_present" | "health_fresh" | "healthy" |
  "desired_generation" | "applied_generation" | "active_recovery" | "latest_deployment_status"
>;

export function nodeOnboardingProgress(node: OnboardingFacts) {
  if (!node.registered) {
    return { ready: false, label: "Ожидаем регистрацию", message: "Запустите команду установки на выбранном сервере." };
  }
  if (!node.online) {
    return { ready: false, label: "Ожидаем связь с агентом", message: "Регистрация сохранена. Ожидаем подключение агента." };
  }
  if (node.active_recovery) {
    return { ready: false, label: "Восстановление", message: "На сервере выполняется восстановление. Ожидаем его завершения." };
  }
  if (!Number.isSafeInteger(node.desired_generation) || node.desired_generation < 0 ||
      !Number.isSafeInteger(node.applied_generation) || node.applied_generation < 0 ||
      node.desired_generation !== node.applied_generation ||
      node.latest_deployment_status === "pending" || node.latest_deployment_status === "applying") {
    return { ready: false, label: "Применение настроек", message: "Агент на связи. Ожидаем применения настроек сервера." };
  }
  if (!node.health_present || !node.health_fresh) {
    return { ready: false, label: "Проверка состояния", message: "Агент на связи. Ожидаем свежий отчёт о его состоянии." };
  }
  if (node.desired_generation > 0 && !node.healthy) {
    return { ready: false, label: "Нужна проверка", message: "Агент сообщает об ошибке. Откройте ноду, чтобы проверить её состояние." };
  }
  return {
    ready: true,
    label: "Агент готов",
    message: node.desired_generation === 0
      ? "Подключение агента завершено. Теперь можно настроить VPN."
      : "Конфигурация применена, агент сообщает об исправной работе.",
  };
}
