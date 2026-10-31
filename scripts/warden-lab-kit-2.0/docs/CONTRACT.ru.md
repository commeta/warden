# Контракт микросервисов и сайты-движки

## Контракт микросервисов

Каждый микросервис отвечает одинаково, поэтому один тест покрывает все рантаймы.
Все слушают `127.0.0.1:31xx` (приватно), фронт проксирует их за `/svc/<имя>/`
через WAF. Реализации используют только стандартную библиотеку рантайма —
стенду не нужен реестр пакетов языка.

| Эндпоинт | Ответ | Что проверяет |
|---|---|---|
| `GET /health` | 200 `ok` | генерируется `[[health.check]]` Warden |
| `GET /echo?q=` | отражает ввод | мишень XSS |
| `GET /item?id=` | строка из SQLite (read-only) | мишень SQLi (сам не уязвим) |
| `POST /upload?name=` | пишет файл в каталог под FIM | фикстуры вебшелла |
| `GET /spawn` | запускает `/usr/bin/id` | `security.web_spawn` по моделям процессов |
| `GET /sleep?ms=` | пауза | health и таймауты |
| `GET /alloc?mb=` | аллокация до 256 МиБ | детектор памяти |

| Сервис | Рантайм | Модель процессов |
|---|---|---|
| `node` | Node.js (stdlib http) | один event loop |
| `python-asgi` | Python asyncio | один цикл |
| `python-wsgi` | Python prefork | несколько воркеров |
| `go` | Go net/http | один статический бинарь |
| `java` | JDK `com.sun.net.httpserver` | JVM, большой RSS |
| `ruby` | Ruby TCPServer, fork | кластер |
| `perl` | Perl IO::Socket, prefork | prefork |
| `php-fpm` | PHP-FPM | пул на сайт |
| `ws` | Node, WebSocket (RFC6455) | долгие соединения, Upgrade через WAF |
| `dotnet` | ASP.NET minimal API | опционально (нужен dotnet SDK) |

Фреймворки (FastAPI, Flask, Fastify, Sinatra, Mojolicious) в бою ставятся в те
же юниты — контракт идентичен; в стенде реализации на stdlib, чтобы установка
не зависела от сети и реестров.

## Сайты-движки

Общий код в `sites/_core/`, у каждого движка — свой `index.php`, задающий
идентичность (имя, generator, админ-путь, cookie, канонические URL, которые
пробуют сканеры). Один набор мишеней (`/lab/xss`, `/lab/sqli`,
`/lab/traversal`, `/lab/cmd`, `/lab/upload`, `/lab/admin-save`, `/lab/info`,
`/lab/batch`) и легитимное действие админки, которое WAF не должен блокировать
(исключения CRS в шаблоне).

| Движок | Админ-путь | Канонические URL (мишени) |
|---|---|---|
| `wordpress` | `/wp-admin/` | `/wp-login.php`, `/xmlrpc.php`, `/wp-admin/post.php` |
| `modx` | `/manager/` | `/manager/`, `/connectors/`, `/assets/components/` |
| `opencart` | `/admin/` | `?route=product/product`, `?route=account/login` |
| `joomla` | `/administrator/` | `?option=com_users`, `?option=com_content` |
| `drupal` | `/user/login` | `/node/add`, `/sites/default/files/`, `?q=node` |
| `bitrix` | `/bitrix/admin/` | `/bitrix/tools/`, `/bitrix/admin/1cv8_runner.php` |
| `portal` | `/` | дашборд со ссылками на сайты и сервисы |

Каждый сайт — свой системный пользователь `lab-<движок>`, свой пул PHP-FPM, свой
docroot и access-log, так что поле `site` в событиях WAF/FIM настоящее, а
вебшелл в `uploads/` атрибутируется этому сайту. Загруженный в `uploads/` PHP
доступен (чтобы сработала корреляция `webshell_access`), но не исполняется — это
безопасно для production.

Каждый микросервис также регистрируется отдельным FIM-сайтом `svc-<имя>` с
корнем `/var/www/warden-lab/services/<имя>`. Для корреляции запросов используется
access-log портала, через который проксируются `/svc/<имя>/`; `uploads/**`
обозначен как каталог, в котором скрипты запрещены. Исходники и build outputs
принадлежат root и доступны сервисной учётной записи только для чтения/исполнения;
запись разрешена только в `uploads/` и `data/`. PHP-FPM использует primary group
сервисной учётной записи, а FastCGI-сокет по-прежнему принадлежит `www-data`.

Браузерные пакетные тесты: `GET /lab/batch` — страница на чистом JS прогоняет
батарею атак из браузера и показывает статус, что вернул WAF (для человека;
авторитетны тесты pytest).
