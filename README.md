# VPN Panel

Самостоятельная VPN-панель для Ubuntu 24.04 amd64. Каждая установка использует собственный домен, базу данных и учётную запись владельца.

## Установка

Нужны чистый Ubuntu 24.04 amd64, 4 ГБ RAM, 12 ГБ свободного места и свободные входящие TCP-порты 80/443. DNS-запись A вашего домена должна указывать на IPv4 сервера.

Подключитесь по SSH от root и выполните:

```bash
curl -fsSL https://raw.githubusercontent.com/djalil055018-ux/vpn-panel/main/install.sh | bash
```

Если `curl` ещё не установлен, сначала выполните `apt-get update && apt-get install -y curl ca-certificates`.

Установщик запросит домен, email для сертификата и пароль владельца длиной от 15 символов. После установки откройте свой домен по HTTPS. Логин по умолчанию: `owner`.

Для передачи параметров явно:

```bash
curl -fsSL https://raw.githubusercontent.com/djalil055018-ux/vpn-panel/main/install.sh -o /tmp/vpn-panel-install.sh
bash /tmp/vpn-panel-install.sh --domain panel.example.com --email admin@example.com
```

Дистрибутив 0.1.155 содержит Control Plane 0.1.150 и Web 0.12.71. Файлы установки и VPN-агентов проверяются по SHA-256. Файлы для подключения VPN-серверов раздаются непосредственно с вашей установки.

## Исходники

- `control-plane/`: серверная часть, миграции и служебные инструменты.
- `web/`: исходники веб-панели.
- `native-agents/`: соответствующие исходники агентов 0.2.39, 0.2.42 и 0.2.43.
- `tools/build-release.py`: сборка Linux amd64 из исходников с проверкой манифеста.
- `node-assets.json`: контрольные суммы файлов для подключения VPN-серверов.

Архивы выпуска доступны в GitHub Releases. Сборка требует Go 1.27.3, Python 3.12 и исходных файлов сторонних рантаймов с контрольными суммами, указанными в `tools/build-release.py`. При установке веб-панель собирается через `npm ci` из зафиксированного lock-файла; доступ к npm, Docker Hub, Node.js и репозиториям Ubuntu необходим.
