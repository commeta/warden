# Warden Lab Kit 2.0

Декларативный лабораторный стенд и **пример архитектуры для адаптации** под [Warden](https://github.com/commeta/warden).
Одна точка входа — `labctl` — по профилю `lab.toml` поднимает веб-фронт с
ModSecurity и CRS, набор сайтов-движков и микросервисов, настраивает Warden и
проверяет, что он правильно реагирует на атаки. Заменяет девять императивных
bash-скриптов 1.x (ревью Lab Kit в `docs/reviews/review-0.14.2.ru.md`).

Это технический стенд: сайты примитивны, их «уязвимые» эндпоинты — мишени,
которые ModSecurity обязан блокировать. По умолчанию используйте выделенную
машину или ВМ. `production-external` — учебный reference-профиль, а не готовая
конфигурация для реального трафика: не публикуйте его в интернет, пока не заменены
эмуляторы сайтов, не проверены DNS/TLS, firewall, allowlist и Warden-политики.

## Быстрый старт — Ubuntu Server 24.04

Для прямого доступа из доверенной LAN используйте установщик. Он создаёт
`lab.toml`, устанавливает зависимости через APT, повторно строит план после
установки пакетов, применяет конфигурацию, устанавливает Warden 0.14.3 с
проверкой SHA-256 и включает службу в observe-only/dry-run режиме:

```bash
sudo ./install.sh --profile lan --iface enp0s8 --trusted 192.168.56.1/32
```

Замените `enp0s8` на интерфейс сервера, доступный из LAN, а адрес в `--trusted`
— на IP хостовой машины. Не используйте `0.0.0.0/0` или `::/0`. Для локального
CI-профиля без доступа извне:

```bash
sudo ./install.sh --profile ci
```

Ручной декларативный путь:

```bash
sudo ./labctl doctor                         # проверка платформы
sudo ./labctl plan                           # план без изменений
sudo ./labctl apply                          # APT dependencies + configuration + Warden
sudo ./labctl verify                         # быстрые проверки всех компонентов
sudo ./labctl test -m "smoke or waf"          # pytest black-box tests
sudo ./labctl reset --yes                    # удалить файлы, принадлежащие Kit
```

`labctl` использует Python 3.12 без сторонних Python-зависимостей. Команда
`apply` автоматически ставит системные пакеты ролей, включая `nftables`,
`iproute2`, `openssl`, `curl`, pytest и необходимые runtimes. После установки
пакетов план рендерится повторно, чтобы использовать файлы, добавленные APT.
Warden закреплён на версии `0.14.3` и опубликованном SHA-256; неизвестные или
непроверенные пакеты не устанавливаются. Пакет Warden `0.14.3` на upstream
странице помечен как pre-release, поэтому для production используйте его только
после отдельного согласования. На первом запуске Warden работает в режиме
наблюдения (`dry_run = true`), автоматическое реагирование не включено.

## Что умеет

- **Декларативный профиль** `lab.toml`: фронт, движок и режим WAF, версия CRS,
  сайты, сервисы, источник Warden, сеть. Проверяется по матрице совместимости
  **до** установки — несовместимый профиль отклоняется на `plan`.
- **Манифест и сверка.** Всё, что kit пишет, записано в
  `/var/lib/warden-lab/state.json` с ролью и SHA-256. `apply` пишет только
  изменившееся, удаляет осиротевшее (так в 1.x logrotate падал три ночи — L1),
  валидирует конфиги (`nginx -t`, `apachectl configtest`, `wardend
  --check-config`) и только потом перезапускает сервисы. Чужой файл по тому же
  пути отодвигается в сторону, а не перетирается.
- **Фронты:** nginx + ModSecurity 3, Apache prefork + mod_php + ModSecurity 2.9,
  Apache event + PHP-FPM, и edge-прокси HAProxy / Caddy перед WAF-уровнем
  nginx + ModSecurity 3 (проверяет цепочку X-Forwarded-For).
- **6 режимов журнала ModSecurity**, которые читает Warden 0.14.3: serial
  native, serial JSON, per-site, concurrent с индексом и без, только error-log.
  `labctl apply --set waf.mode=…` переключает их на одном стенде.
- **Сайты-движки:** WordPress, MODX, OpenCart, Joomla, Drupal, 1C-Bitrix и
  портал. Каждый — свой пользователь, свой пул PHP-FPM, свой docroot, свой
  access-log (`site` в событиях Warden настоящий). Общий набор мишеней
  (`/lab/xss`, `/lab/sqli`, `/lab/traversal`, `/lab/upload`, …) и браузерные
  пакетные тесты на `/lab/batch`.
- **Микросервисы** по контракту (`/health`, `/echo`, `/item`, `/upload`,
  `/spawn`, `/sleep`, `/alloc`) на 9 рантаймах (Node, Python ASGI/WSGI, Go,
  Java, Ruby, Perl, PHP-FPM, WebSocket; .NET — опционально), каждый под своим
  пользователем и ужесточённым юнитом systemd, за `/svc/<имя>/` через WAF.
- **Сеть:** loopback (только локально), LAN (веб-фронт доступен с выбранного интерфейса только доверенным CIDR), netns (клиент и атакующий в своих namespace, настоящий дроп Warden не на `lo`, ротация IPv6 /64), external (production: фронт на реальном интерфейсе, новые подключения ограничиваются по скорости, сервисные порты закрыты).
- **Генерация drop-in Warden** из профиля: `[[waf.log]]` под режим,
  `process.web_users`, `[[fim.site]]`, `[[health.check]]`, allowlist,
  `ipv6_prefix`. Синтетическая (безвредная) сигнатура вебшелла для тестов FIM.
- **Внешние тесты** (pytest, чёрный ящик): `smoke`, `waf`, `warden`, `enforce`,
  `ipv6`, `forgery`, `fim`, `spawn`, `health`. Каждый запрос несёт `t=<uuid>`,
  и событие ищется по нему — тест нельзя пройти на вчерашних событиях (L3).
- **stress / soak / report / test-upgrade** с порогами из плана 0.15.

## Профили

| Профиль | Фронт | WAF | Сеть | Назначение |
|---|---|---|---|---|
| `ci-nginx-modsec3` | nginx | ModSecurity 3, serial-json | loopback | основной CI |
| `lan-nginx-modsec3` (пример) | nginx | ModSecurity 3, serial-json | lan | браузерный доступ из доверенной LAN (сначала настройте интерфейс и CIDR) |
| `apache-modsec2` | Apache prefork | ModSecurity 2.9, serial-native | loopback | классический стенд |
| `full` | nginx | ModSecurity 3, concurrent | netns | все сайты и сервисы, IPv6 |
| `production-external` | nginx | ModSecurity 3 | external | эталон production |

## Документация

- `docs/ARCHITECTURE.ru.md` — роли, матрица совместимости, манифест, сеть.
- `docs/PRODUCTION.ru.md` — как использовать профиль `external` как эталон
  production (TLS, заголовки, firewall, ограничение скорости, enforce).
- `profiles/lan-nginx-modsec3.example.toml` — шаблон LAN-профиля с allowlist источников.
- `docs/INSTALL_UBUNTU_24.ru.md` — автоматическая установка на чистый Ubuntu Server 24.04.
- `docs/TEST-MATRIX.ru.md` — что проверяется и критерии приёмки.
- `docs/MIGRATION.ru.md` — переход с Lab Kit 1.x (`labctl migrate`).
- `docs/CONTRACT.ru.md` — контракт микросервисов и список сайтов-движков.

## Команды `labctl`

| Команда | Что делает |
|---|---|
| `doctor` | проверка предусловий хоста под выбранный профиль |
| `plan` | что изменит `apply` (ничего не пишет; можно без root) |
| `apply` | установить пакеты, свести файлы с профилем, поднять сервисы |
| `verify` | быстрые проверки после `apply` |
| `test [-m МАРКЕР] [--enforce]` | внешние тесты pytest против стенда |
| `stress [сценарий]` | враждебная нагрузка с порогами |
| `soak --hours N` | длительный прогон: RSS/рестарты/потери Warden |
| `report [--json]` | пакеты, события окна по видам, что принадлежит kit |
| `test-upgrade --from-deb … --to-deb …` | обновление Warden N-1 → N → откат |
| `migrate` | `lab.env` (1.x) → `lab.toml` |
| `crs-digest <тег>` | хеш дерева тега CRS (чтобы закрепить `crs.sha256`) |
| `reset --yes` | снести всё, что принадлежит kit |
