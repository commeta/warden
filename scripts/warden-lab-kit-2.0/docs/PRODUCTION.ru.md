# Lab Kit 2.0 как эталон production

Профиль `production-external.toml` — **пример архитектуры для адаптации**, а не
готовая к публикации production-система. Он показывает front на реальном
интерфейсе, TLS, security headers, firewall, ограничение скорости и Warden в
observe/dry-run. Сайты из Kit остаются тестовыми эмуляторами: не открывайте их
в интернет и не используйте с реальным трафиком, пока не замените их проверенными
приложениями и не проведёте собственное security review.

## Перед запуском

Отредактируйте профиль:

```toml
[lab]
name = "production"
front = "nginx"
hostname = "example.com"       # ваш реальный домен
production = true               # HTTP→HTTPS, HSTS, server_tokens off
sites = ["portal", "wordpress"]
services = ["php-fpm", "node"]
databases = ["mariadb", "redis"]

[net]
mode = "external"
external_iface = "eth0"         # NIC, на котором слушает фронт
trusted = ["203.0.113.0/24", "2001:db8:1::/48"]  # ваши админ/мониторинг-сети

[tls]
mode = "acme"                   # Let's Encrypt (или "files" со своим сертификатом)
domains = ["example.com", "wordpress.example.com"]  # основной + vhost WordPress
acme_email = "admin@example.com"
acme_staging = false

[waf]
engine = "modsec3"
mode = "concurrent-index"
paranoia = 2                    # для production 2 — разумный минимум

[crs]
source = "package"              # автоматический путь; 4.x можно включить с зафиксированным sha256
# source = "4.x"
# ref = "v4.18.0"
# sha256 = "<хеш из labctl crs-digest v4.18.0>"

[warden]
source = "release"
version = "0.14.3"
sha256 = "acc3e47112307cacdf4e025570f99e0afcc4131cf9e5395b554daaf68bc5470c"
enforce = false                 # сначала observe/dry-run; включайте после разбора событий
```

## Что даёт `production = true` + `external`

- **TLS везде.** HTTP (кроме `/.well-known/acme-challenge/`) редиректит на
  HTTPS (308). HSTS `max-age=2 года; includeSubDomains`. Современные протоколы
  и шифры (TLS 1.2/1.3), `ssl_session_cache`.
- **Заголовки безопасности** на каждый ответ: `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`;
  `server_tokens off`.
- **Firewall.** `inet lab_filter` на реальном NIC: порты микросервисов
  (`3100-3199`) никогда не выставлены наружу; новые HTTP-соединения с одного
  адреса ограничены (120/мин, burst 60) как грубый бэкстоп; доверенные сети из
  `net.trusted` этот лимит обходят. Настоящую блокировку атакующих делает Warden
  в своей таблице `inet warden` на более высоком приоритете.
- **Warden в allowlist знает ваши сети.** `net.trusted` + адрес клиента
  попадают в `actions.firewall.allowlist`, а `protect_ssh_sessions = true` — так
  блокировка (в тесте или в бою) не может закрыть вам доступ. `ipv6_prefix = 64`:
  атакующий с ротацией IPv6 внутри /64 блокируется сетью.
- **Ужесточённые сервисы.** Каждый микросервис — свой системный пользователь и
  юнит с `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`,
  `SystemCallFilter=@system-service`, `CapabilityBoundingSet=` (пусто),
  `ReadWritePaths` только на свои `uploads`/`data`.
- **Каждый сайт изолирован.** Свой пользователь и пул PHP-FPM с `open_basedir`,
  отключёнными опасными функциями, docroot только для чтения воркером (пишет
  только `uploads/`, где исполнение PHP запрещено и на nginx, и на Apache).

## Включение enforce

Пакет Warden закреплён на `0.14.3` по версии и SHA-256. На странице upstream
этот тег помечен как pre-release; для строгого production-эксплуатационного
контура согласуйте этот выбор с владельцем Warden перед rollout.

`enforce = true` ставит Warden с `daemon.dry_run = false` в drop-in. Этот флаг
не включается автоматически ни в одном примере. Рекомендуемый порядок всё равно консервативен:

1. Сначала разверните с `enforce = false`, посмотрите сутки
   `wardenctl events -f` и `labctl report`, погасите ложные срабатывания
   политиками Warden.
2. Затем `enforce = true` и `labctl apply`, либо `wardenctl dry-run off` на живом
   демоне (переживает reload и restart).

## Чего профиль не делает

Это эталон конфигурации Warden и веб-уровня, а не всей инфраструктуры. Резервные
копии, обновления ОС, мониторинг, ротацию секретов БД, DNS и балансировку вы
настраиваете отдельно. Сайты-движки — эмуляторы для проверки WAF; для реального
WordPress поставьте настоящий код в тот же docroot (роль `app_php` задаёт
владельца, пул и FIM-слежение — подходят и для настоящего CMS).
