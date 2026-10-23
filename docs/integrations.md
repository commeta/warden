# Интеграции: веб-стеки, ModSecurity, базы данных, микросервисы

## Веб-серверы и PHP SAPI

Warden не встраивается в веб-сервер — он следит за **файлами** (FIM) и
**процессами** (proc connector). Поэтому он одинаково работает с любым сервером
и любым способом запуска PHP, Node, Python или Ruby. От стека к стеку отличается
*какой процесс исполняет код запроса* и *под каким пользователем*; значения по умолчанию
покрывают типовые конфигурации:

| стек | процесс, исполняющий код запроса | пользователь | покрыт |
|---|---|---|---|
| nginx + PHP-FPM | воркеры пула `php-fpm8.x` | `www-data` или один пользователь на пул | `web_comms` (`php-fpm*`) + не-root, `web_users` |
| Apache + mod_php (prefork) | воркеры `apache2` / `httpd` | `www-data` / `apache` | `web_comms` + не-root (мастер под root игнорируется) |
| Apache + PHP-FPM (proxy_fcgi) | воркеры `php-fpm*` | пользователь пула | как nginx + FPM |
| Apache + mod_fcgid / FastCGI | процессы `php-cgi`, порождённые Apache | `www-data` или suEXEC-пользователь | `web_comms` (`php-cgi*`) |
| Apache + suEXEC / mpm-itk / mod_ruid2 | воркеры, переключённые на владельца сайта | пользователь сайта | `web_comms` + не-root (работает без перечисления каждого пользователя сайта) |
| CGI (mod_cgi, nginx + fcgiwrap) | скрипты `perl`/`python`/`sh` | `www-data` | разрешить скрипты по пути: `[[process.allowed_children]] parent = "apache2", child = "/usr/lib/cgi-bin/**"` |
| LiteSpeed / OpenLiteSpeed | `lsphp` | пользователь сайта | `web_comms` (`lsphp*`, `litespeed`, `lshttpd`) |
| FrankenPHP, HHVM | `frankenphp`, `hhvm` | пользователь сервиса | `web_comms` |
| Node.js / Deno / Bun | `node`, `deno`, `bun` | пользователь сервиса | `web_comms` |
| Python (gunicorn, uWSGI, uvicorn, daphne) | именованные воркеры | пользователь сервиса | `web_comms` |
| Ruby (puma, unicorn, Passenger), Java (Tomcat), .NET | именованные воркеры | пользователь сервиса | `web_comms` |

«Не-root» важен: мастер-процессы Apache/nginx работают под root и
законно запускают хелперы (piped loggers вроде `rotatelogs`, тесты конфигурации);
код запроса всегда исполняется в непривилегированных воркерах. Warden считает веб-воркерами
только не-root-процессы с такими именами — плюс всё, что работает под
учётной записью из `web_users`.

FIM тоже не привязан к серверу: укажите `[[fim.site]] root` на корень документов,
а `access_log` — на access-log сервера в формате combined/common (по умолчанию у
nginx и Apache).

**Обновления CMS и плагинов.** Обновление через админку CMS (WordPress,
Joomla, Bitrix, `npm`/`composer`-прогон от PHP-воркера) меняет сотни
файлов, записанных тем же PHP-воркером, которым воспользовалась бы и инфекция. Warden
отличает одно от другого по содержимому: массовое изменение убивает писателей, только когда их собственные
записи совпали с сигнатурами; всплеск чистых изменений — это
предупреждение `fim.mass_change`. Ставьте FIM на паузу вокруг плановых обновлений, чтобы
изменения принимались в baseline — они всё равно сканируются, и
вредоносный код всё равно сообщается и отправляется в карантин:

```bash
wardenctl fim pause main 30m     # перед обновлением (имя сайта из [[fim.site]])
# ... обновление ...
wardenctl fim accept main        # если что-то осталось принять
```

Деплои через `git`, `rsync` и другие инструменты из `fim.trusted_writers`
принимаются без паузы.

## ModSecurity (v2 и v3)

| | ModSecurity v2 (`mod_security2`) | ModSecurity v3 (libmodsecurity) |
|---|---|---|
| серверы | Apache httpd | nginx (коннектор ModSecurity-nginx), коннектор Apache |
| пакеты Debian/Ubuntu | `libapache2-mod-security2` | `libmodsecurity3` + `libnginx-mod-http-modsecurity` |
| что читает Warden | `SecAuditLog` (нативный или JSON) и/или Apache `error.log` | `SecAuditLog` (нативный или JSON) и/или nginx `error.log` |

Обе ветки поддерживаются под эгидой OWASP; набор правил, который использует большинство, —
OWASP Core Rule Set (CRS). Warden **не** заменяет ModSecurity — он добавляет
то, чего WAF на уровне запроса не умеет:

* **память между запросами**: считает заблокированные транзакции по IP клиента и,
  после `waf.block_after` в пределах `waf.window`, блокирует адрес в nftables
  на `block_ttl` (как fail2ban, но без обслуживания регулярных выражений под каждый
  дистрибутив);
* **эвристический скоринг**: каждый настойчивый атакующий добавляет `waf_attack` очков
  к оценке подозрительности IP, общей с SSH-брутфорсом, доступом к веб-шеллу…;
* **корреляция с файловой системой**: когда скрипт появляется или меняется,
  список подозрительных запросов FIM ставит первыми клиентов, которых пометила ModSecurity
  (`waf_hits`, `waf_rules`) — обычно это атакующий, нашедший дыру.

Минимальная настройка:

```toml
# /etc/warden/conf.d/60-modsecurity.toml
[[waf.log]]
path = "/var/log/apache2/modsec_audit.log"   # или /var/log/nginx/error.log
site = "main"                                # [[fim.site]], который он защищает
```

Форматы определяются построчно (`format = "auto"`): JSON-аудит-логи обеих
веток, нативный серийный аудит-лог (`--xxxx-A--` / `---xxxx---A--`) и
строки error-log (`ModSecurity: Access denied ...`). Один запрос, залогированный
несколькими строками (по одной на совпавшее правило), считается один раз по своему `unique_id`.

Настройки тонкой подстройки: `min_rule_severity` (по умолчанию `critical`), `ignore_rules` для ложных
срабатываний CRS на ваших приложениях, `count_detection_only` пока
ModSecurity работает в режиме `DetectionOnly`.

## Базы данных

* **Никогда не жертва OOM случайно** — серверы БД находятся в `memory.culprit.avoid`
  (оценка × 0.2, × 0.05 в профиле database). Установка `OOMScoreAdjust=-800`
  в юните БД заставляет и ядро, и Warden её пропускать.
* **Данные никогда не чистятся** — `/var/lib` жёстко защищён от любого действия очистки
  и карантина.
* **Здоровье**: «процесс работает» ≠ «база отвечает». Используйте командные
  проверки: `mysqladmin ping`, `pg_isready`, `redis-cli ping` (примеры в
  `config/conf.d/50-database.toml`). После `failures` промахов подряд Warden
  снимает снимок и перезапускает юнит, затем ждёт `grace` (восстановление InnoDB/WAL),
  прежде чем судить снова.
* **SQL-инъекция → выполнение команд**: shell или инструмент, запущенный
  `mysqld`, `postgres`, `redis-server`, `mongod`… поднимает `security.db_spawn`
  (critical и убивается, когда командная строка — загрузчик/reverse shell).
  `archive_command` PostgreSQL законно идёт через `sh -c` — разрешите это
  через `[[process.allowed_children]] parent = "postgres"`.
* **UDF-бэкдоры**: новые или изменённые `.so`-файлы в `/usr/lib/mysql/plugin/`
  сообщаются детектором целостности.
* **Настройки ядра для баз данных**: `wardenctl tuning` помечает THP=always при
  Redis/MongoDB, высокий swappiness на хостах с БД, `vm.max_map_count` для Elasticsearch
  и процентные dirty-лимиты на машинах с большим объёмом RAM.

## Микросервисы и контейнеры

* **Проверки здоровья** (`[[health.check]]`, `type = "http" | "tcp" | "command"`)
  работают в собственном потоке: один зависший endpoint никогда не задерживает другие детекторы.
* **Атрибуция**: события процессов несут `container=` — `docker:<name>` (драйверы systemd
  и cgroupfs), `podman:<id>`, `k8s:pod-<uid>/<container>`,
  `lxc:<name>`, `machine:<name>` (systemd-nspawn).
* **Какой сервис тормозит**: события давления на память перечисляют cgroups с
  наибольшим PSI памяти (`most_stalled_cgroups`), а не только самые большие.
* **OOM по лимиту cgroup**: когда сервис или контейнер упирается в свой
  `MemoryMax`/лимит контейнера, событие так и говорит — «api.service упёрся в свой лимит
  памяти» — вместо общего OOM.
* **Внутри контейнера**: пороги памяти используют лимит cgroup контейнера
  и его собственный PSI, а не хоста.
* **Действия над сервисами**: `restart_unit`, `freeze_cgroup`/`kill_cgroup`
  (cgroup v2), `limit_unit` (на лету `CPUQuota=`/`MemoryHigh=`/`MemoryMax=`).

## Долго работающие и зависшие процессы

| ситуация | как это видит Warden | типичное действие |
|---|---|---|
| PHP-скрипт в бесконечном цикле | `[[process.limit]]` `cpu_percent` в течение `cpu_duration` | `kill` (FPM поднимает нового воркера) |
| CGI/CLI-скрипт, работающий часами | `[[process.limit]]` `max_runtime` | `kill` или `throttle` |
| воркер течёт по памяти | `[[process.limit]]` `max_rss` | report, `restart_unit` |
| бэкап/дамп мешает продакшену | `[[process.limit]]` на `mysqldump`, `pg_dump`… | `throttle` (nice 19 + idle I/O) |
| сервис жив, но не отвечает | `[[health.check]]` | snapshot + `restart_unit` |
| задача застряла в ядре (NFS, умирающий диск) | `process.uninterruptible`, `kernel.hung_task` | snapshot (сигналы не помогут: чините хранилище) |
| весь хост завис | `system.stall` (опоздание планировщика) | snapshot, снятый *во время* зависания |

## Тюнинг ядра — что Warden делает и что нет

Динамический тюнинг звучит привлекательно, но большинство sysctl меняют задержку на
пропускную способность или безопасность на производительность, а автоматическое изменение в
03:00 — это изменение, которое никто не проверял. Поэтому Warden их разделяет:

* **Ёмкостные лимиты** — таблицы и счётчики, которые заставляют ядро *отказывать в работе*
  при исчерпании: `nf_conntrack_max` (новые соединения отбрасываются), `kernel.pid_max`
  (fork падает), `fs.file-max` (open падает). При `[tuning] auto_grow = true`
  Warden удваивает их, когда детектор лимитов видит их почти полными, никогда
  сверх вычисленного из RAM потолка, журналирует исходное значение
  (`wardenctl tuning --revert` восстанавливает всё) и, при `persist = true`,
  пишет `/etc/sysctl.d/90-warden.conf`.
* **Поведенческие настройки** — swappiness, dirty-ratio, overcommit, THP, somaxconn,
  sysctl укрепления безопасности: только **рекомендуются**, с причиной и
  замером, который их вызвал (`wardenctl tuning`).

«Сколько памяти есть» отвечается динамически: пороги памяти масштабируются
под RAM (`memory.auto_scale`) и следуют лимиту cgroup внутри контейнеров.
