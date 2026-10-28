<div align="center">

# 🛡️ Warden

**Демон-хранитель хоста для Linux-серверов и рабочих станций — полностью написан на Rust.**

Warden следит за здоровьем машины и *действует*, когда что-то идёт не так: он ловит
нехватку памяти и свопинг-штормы **до** OOM-killer'а, до того как сервер
«зависнет на десять минут»; не даёт дискам заполняться; обнаруживает и
сдерживает вторжения — веб-шеллы, обратные шеллы, майнеры, повышение привилегий,
персистентность — с безопасной, настраиваемой автоматической реакцией.

[Архитектура](docs/architecture.md) · [Детекторы и события](docs/detectors.md) · [Замечания по безопасности](docs/security.md) · [Эталонная конфигурация](config/warden.toml)

[![build](https://github.com/commeta/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/commeta/warden/actions/workflows/ci.yml) ![status](https://img.shields.io/badge/status-beta-orange) ![rust](https://img.shields.io/badge/rust-1.88%2B-informational) ![platform](https://img.shields.io/badge/platform-Linux%204.20%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Зачем нужен Warden

`free -h` врёт вам. К тому моменту, когда он показывает мало памяти, ядро уже
секундами приостанавливает ваши процессы, освобождая и повторно подгружая страницы,
и машина недоступна по SSH. Классический мониторинг сообщает вам *после*
инцидента. Warden использует **Pressure Stall Information (PSI)** ядра —
фактическое время, которое ваши задачи теряют в ожидании памяти, CPU и ввода-вывода —
чтобы увидеть, как проблема назревает, и либо отправить вам оповещение, либо убить нужный
процесс *до* того, как машина зависнет.

Тот же демон следит за обыденными катастрофами, которые валят серверы в
3 часа ночи (журнал, заполняющий корневую файловую систему, файловая система, перешедшая в режим только чтения,
переполненная таблица conntrack, упавший юнит), и за умышленными (PHP-воркер,
запускающий `curl … | sh`, веб-шелл, появляющийся в `wp-content/uploads`,
процесс, ставший root в обход `sudo`, новый SUID-бинарник в
`/tmp`). Первый тип он может исправить автоматически, а второй — сдержать, и всё
это под строгими правилами безопасности, чтобы он никогда не убил вашу базу данных или вашу SSH-сессию.

Один самодостаточный бинарник (динамически слинкован только с glibc ≥ 2.34 и
libgcc). Никакого агента в ядре, никакого eBPF-тулчейна, никакого Python-рантайма.
`.deb` устанавливается и работает на Debian 12, Ubuntu 22.04 и 24.04 (проверено в CI);
любой Linux с glibc 2.34+ запускает его из тарбола (функции ядра: см.
[Совместимость](#compatibility)).
Достаточно мал для VPS с 1 GiB: ~10 MiB RSS с типичным набором детекторов,
~33 MiB со всеми включёнными модулями и сайтом на 20 000 файлов под FIM; у отключённого
модуля нет ни потока, ни памяти вообще ([измерения](docs/performance.md)).

## Основные возможности

- **Давление памяти и свопинг-штормы (PSI).** Обнаруживает устойчивые остановки и
  трэшинг с настраиваемым временем обнаружения, регистрирует PSI-триггер ядра
  для мгновенного пробуждения, ранжирует настоящего виновника (что освободит убийство —
  анонимная память + своп — плюс OOM-badness и активность подкачки) и может
  убить его до того, как OOM-killer ядра выберет не ту жертву; убийство, которое
  не освобождает память, останавливает дальнейшие убийства для этого эпизода. Warden `mlock`-ит себя, чтобы оставаться отзывчивым, пока хост
  трэшит.
- **Обнаружение зависания всего хоста.** Измеряет, насколько поздно просыпается его собственный высокоприоритетный,
  залоченный в памяти планировщик — прямой сигнал о том, что машина была
  неотзывчива, с диагностическим снимком, снятым во время зависания.
- **Самовосстановление дисков.** Пространство, inodes, перемонтирование в режим только чтения и *прогноз*
  скорости заполнения. Упорядоченный сценарий очистки (vacuum journald, `apt clean`,
  удаление старых логов, усечение огромных логов, освобождение удалённых, но открытых файлов) выполняется
  только на затронутой файловой системе и никогда не трогает системные каталоги. Когда
  очистка не помогает, ограниченный фоновый `du` сообщает **кто использует
  диск** (крупнейшие каталоги и файлы) — `wardenctl du` делает то же самое по
  требованию.
- **Обнаружение вторжений с событиями процессов в реальном времени.** Через netlink
  **proc connector** (без eBPF): повышение привилегий, бесфайловое выполнение, обратные шеллы,
  крипто-майнеры, маскировка процессов, инъекция LD_PRELOAD,
  инъекция через ptrace и веб-воркеры, порождающие шеллы/загрузчики. Повторные
  доброкачественные exec'и (сборочные серверы, штормы cron) идут по быстрому пути, читающему один
  файл `/proc` вместо шести.
- **Мониторинг целостности веб-файлов.** BLAKE3-базлайны каждого скрипта на ваших
  сайтах, проверяемые по расписанию *и* в реальном времени через **fanotify** (который
  сообщает **PID писателя** — точный воркер, заразивший файл). Движок сигнатур помечает
  веб-шеллы/дропперы в PHP, Node, Python, JSP/ASP и трюки в `.htaccess`; корреляция с логами доступа называет запрос, который посадил
  файл, и блокирует IP-адреса, использующие шелл.
- **Целостность системы и аутентификация.** Базлайны `/etc/passwd`, sudoers, SSH-ключей,
  cron, systemd-юнитов, `ld.so.preload`, PAM… (с проверкой контрольных сумм dpkg
  чтобы обновления пакетов не были ложными срабатываниями), видит новый SUID/SGID-файл **в
  момент его появления** (метки файловых систем fanotify; еженедельный обход остаётся
  страховкой), следит за слушающими сокетами и разбирает journald/auth.log на предмет SSH brute force (с
  автоматической блокировкой), root-логинов и изменений учётных записей.
- **Интеграция с ModSecurity (v2 и v3).** Читает журнал аудита (нативный или
  JSON) или лог ошибок Apache/nginx, блокирует клиентов, которых ModSecurity продолжает
  останавливать (он оценивает запросы, Warden запоминает атакующих) и ставит IP-адреса, помеченные WAF, первыми при поиске
  запроса, который посадил веб-шелл.
- **Работает с любым веб-стеком.** nginx, Apache, LiteSpeed; PHP через FPM,
  mod_php, CGI/FastCGI/mod_fcgid, suEXEC/mpm-itk с per-site пользователями; Node, Python,
  Ruby, Java-серверы приложений — см. [docs/integrations.md](docs/integrations.md).
- **Упавшие systemd-юниты в реальном времени.** Изменения состояния юнитов приходят по
  D-Bus (никакого процесса `systemctl` каждые 30 с); опциональный авто-рестарт с
  почасовым бюджетом.
- **Зависшие сервисы, микросервисы, базы данных.** HTTP/TCP/command health-проверки
  перезапускают сервисы, которые живы, но не отвечают (`pg_isready`,
  `redis-cli ping`, `/health`); правила `[[process.limit]]` дросселируют или убивают
  застрявшие скрипты (CPU за N минут, время жизни, RSS); база данных, порождающая шелл
  (SQLi → RCE), обнаруживается; события называют контейнер Docker/Podman/Kubernetes
  и сервис, чей собственный лимит памяти был достигнут.
- **Адаптируется к машине.** Пороги памяти масштабируются с RAM и следуют
  лимиту cgroup внутри контейнеров. Советник по тюнингу объясняет, какие sysctl не
  соответствуют вашему железу и нагрузке; лимиты ёмкости (conntrack, pid_max,
  file-max) могут расти автоматически в пределах производных от RAM ограничений — поведенческие ручки
  никогда не меняются у вас за спиной.
- **Эвристическое скоринг.** Отдельные находки накапливают подозрительность по процессам и IP
  с экспоненциальным затуханием; пересечение порога сдерживает процесс
  или блокирует адрес. Он также изучает нормальную
  родительско-дочернюю линию каждого сервиса и помечает никогда не виденные.
- **Безопасная авто-реакция.** kill (без гонок через pidfd), SIGSTOP для
  форензики, throttle (nice + idle I/O), заморозка/убийство cgroup, перезапуск юнита,
  runtime-лимиты юнита, карантин файла (даже сделанного `chattr +i`), блокировка
  IP (nftables с таймаутами ядра), ограниченный рост sysctl, диагностические
  снимки, очистка или ваш собственный хук. Списки защищённых процессов, автоматические выключатели, кулдауны по цели,
  защита путей и глобальный **dry-run** держат это безопасным.
- **Управляемость.** Prometheus `/metrics` и `/health`, журнал событий JSON-lines,
  уведомления Slack/Mattermost/Telegram/command, богатый
  `wardenctl`, живая перезагрузка конфигурации и офлайн `wardenctl doctor`.

## Как это выглядит

```console
$ wardenctl status
Warden 0.14.2 on web-01 — pid 914, up 6days 2h  
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

# 2. Соберите как обычный пользователь — никогда с sudo
git clone https://github.com/commeta/warden && cd warden
cargo build --release

# 3. Установите как root (профили: webserver | workstation | database)
sudo ./scripts/install.sh --profile webserver
# отредактируйте /etc/warden/warden.toml и conf.d/ (как минимум: корни сайтов FIM, allowlist фаервола);
# он стартует в режиме только наблюдения (dry_run = true) — см. "Быстрый старт и безопасное развёртывание"
sudo wardenctl doctor
sudo systemctl enable --now wardend
```

`install.sh`, запущенный через sudo, собирает от имени вызывающего пользователя с *его*
тулчейном, если бинарники отсутствуют или устарели, так что можно также пропустить шаг 2.
Повторный запуск обновляет бинарники и юнит, сохраняет вашу конфигурацию (новые
эталонные файлы кладутся рядом как `*.new`) и перезапускает работающий сервис.

Для сборки требуется Rust ≥ 1.88 (edition 2024 `let` chains). Рекомендуемые runtime-инструменты: `nftables` (блокировка
IP) и `systemd`/`journalctl` (события аутентификации, vacuum журнала). Warden
изящно деградирует без них — `wardenctl doctor` говорит, чего стоит каждый
отсутствующий компонент.

### Пакет Debian / Ubuntu

```bash
./scripts/build-deb.sh            # от имени обычного пользователя → target/debian/warden_0.14.2-1_amd64.deb
sudo apt install ./target/debian/warden_*.deb
./scripts/build-deb.sh --portable # для других машин: слинкован в контейнере Ubuntu 22.04 (docker/podman),
                                  # → target/portable/debian/…, устанавливается на Debian 12, Ubuntu 22.04 и новее
```

Обычная сборка требует glibc машины, на которой она собрана (2.39 на
Ubuntu 24.04), и её пакет это указывает; собирайте с `--portable` для
пакета, устанавливаемого в другом месте.

Пакет устанавливает оба бинарника, systemd-юнит (не включён и не
запущен), эталонную конфигурацию как conffile (`dry_run = true`) и примеры
drop-in'ов/сигнатур в `/usr/share/warden/`. Включите его сами после
проверки конфигурации: `sudo systemctl enable --now wardend`. Обновление
перезапускает работающий сервис и оставляет остановленный в покое.

### Устранение проблем с установкой

| симптом | причина | исправление |
|---|---|---|
| `sudo ./scripts/install.sh` → `cargo not found` | sudo сбрасывает `PATH` (`secure_path`), rustup живёт в `~/.cargo/bin` | исправлено в 0.10: скрипт находит ваш тулчейн; или `cargo build --release` сначала, затем `sudo ./scripts/install.sh --no-build` |
| `rustup could not choose a version of cargo to run` | cargo запущен как root с вашим `PATH`, но у root нет rustup default | собирайте как ваш пользователь (выше); не запускайте cargo через sudo |
| `cargo install cargo-deb` → `Permission denied (os error 13)` в `~/.cargo/registry` | более ранний `sudo -E … cargo` записал файлы, принадлежащие root, в ваш домашний каталог | `sudo chown -R "$USER": ~/.cargo ~/.rustup ./target` (install.sh 0.10 исправляет это автоматически) |
| `wardend.service: Main process exited, code=dumped, status=31/SYS` | seccomp-фильтр юнита 0.9 убил демон (fanotify/adjtimex не разрешены) | установите 0.10 (`sudo ./scripts/install.sh`), затем `sudo systemctl reset-failed wardend && sudo systemctl restart wardend`; `wardenctl doctor` проверяет установленный юнит |
| сенсор показывает `unavailable … (os error 1)` | отсутствует capability или вызов заблокирован кастомизированным юнитом | `wardenctl doctor` называет, какой именно |

## Быстрый старт и безопасное развёртывание

Warden поставляется безопасным: деструктивные действия консервативны, и каждое из них
ограничено. Рекомендуемый путь:

1. Начните в **dry-run**. Это поставляемый по умолчанию режим (`dry_run = true` в
   `warden.toml`; и `install.sh`, и `.deb` оставляют его включённым): Warden
   всё обнаруживает и сообщает, но ничего не меняет. Что он *сделал бы* —
   есть в журнале событий — см. [docs/events.md](docs/events.md) для
   каждого события и значения его полей.
2. Понаблюдайте день: `wardenctl events -f`, `wardenctl scores`,
   `wardenctl top`.
3. Заглушите ложные срабатывания правилами `[[policy]]` (скопируйте `subject`/`cmdline` события
   в правило `suppress` или `alert_only`).
4. Включите реакцию: `wardenctl dry-run off` вступает в силу немедленно и
   сохраняется через перезагрузки и перезапуски (хранится в каталоге состояния;
   `wardenctl status` показывает, что определило режим, `wardenctl dry-run reset`
   возвращает к конфигурации). Или установите `dry_run = false` в `warden.toml`
   и выполните `systemctl reload wardend` (или установите с `install.sh --enforce`);
   изменение `dry_run` в конфигурации побеждает более старый override.

## Конфигурация

Всё живёт в `/etc/warden/warden.toml`, с drop-in'ами в
`/etc/warden/conf.d/*.toml` (сливаются по порядку; списки записей, такие как
`[[fim.site]]`, `[[policy]]`, `[[health.check]]`, добавляются, всё
остальное — включая сценарии, такие как `disk.cleanup` или `memory.on_critical` —
заменяется). Пустой файл валиден — у каждой настройки есть
разумный production-дефолт. Опечатка — это ошибка запуска, а не молча проигнорированная
настройка:

```bash
wardend --check-config          # проверить
wardend --print-defaults        # выгрузить все дефолты как TOML с комментариями
```

Полностью прокомментированный [`config/warden.toml`](config/warden.toml) документирует каждую
опцию. Минимальное дополнение для веб-сервера:

```toml
# /etc/warden/conf.d/90-sites.toml
[[fim.site]]
name = "main"
root = "/var/www/html"
access_log = "/var/log/nginx/access.log"
restart_unit = "php8.3-fpm.service"

[actions.firewall]
allowlist = ["127.0.0.0/8", "::1/128", "198.51.100.0/24"]   # ваши админ/мониторинг-сети

[systemd]
auto_restart = ["nginx.service", "php8.3-fpm.service"]
```

### Та самая ручка времени обнаружения, о которой вы спрашивали

```toml
[memory.swap_storm]
sustain = "60s"   # как долго должен длиться устойчивый свопинг до того, как Warden действует
                  # ("долгий свопинг, когда сервер зависает надолго")
```
и PSI-триггер ядра для мгновенной реакции:
```toml
[memory.trigger]
enabled = true
kind    = "some"     # или "full"
stall   = "150ms"    # как: echo "some 150000 1000000" > /proc/pressure/memory
window  = "1s"
```

## Шпаргалка по `wardenctl`

| команда | что делает |
|---|---|
| `wardenctl status` | уровни, сенсоры, состояние обучения |
| `wardenctl events [-n N] [-s warning] [-f]` | недавние события (следить с `-f`) |
| `wardenctl top` | ранжирование виновников памяти (кто будет убит и почему) |
| `wardenctl scores` | живые эвристические оценки подозрительности |
| `wardenctl mem-top --interval 2s` | RSS/swap/major-faults-в-секунду по процессам |
| `wardenctl psi` | текущий PSI для cpu/memory/io |
| `wardenctl fim status \| scan [site] \| accept <site> [path] \| pause <site> 30m` | управление FIM (пауза вокруг деплоев) |
| `wardenctl block <ip> [--ttl 1h] \| unblock <ip> \| blocklist` | фаервол |
| `wardenctl quarantine list \| restore <id>` | файлы в карантине |
| `wardenctl snapshot [reason]` | снять диагностический снимок сейчас |
| `wardenctl tuning [--revert]` | советы по тюнингу ядра; изменения sysctl, сделанные Warden (и их откат) |
| `wardenctl profile [-i 10]` | **собственные** CPU / I/O / память Warden по потокам, по детекторам и по heap-скоупам |
| `wardenctl doctor` | **офлайн**-проверка возможностей хоста + диагностика установленного юнита (seccomp/caps/сбой) |
| `wardenctl scan /var/www` | **офлайн**-сканирование дерева по сигнатурам |
| `wardenctl du [/var] [-d 2] [-n 15] [--idle]` | **офлайн**-кто использует диск: крупнейшие каталоги по уровням и файлы (одна файловая система, с ограничениями) |

## Наблюдаемость

`http://127.0.0.1:9184/metrics` (Prometheus) отдаёт PSI-метрики, память/своп,
использование диска и ETA заполнения по точкам монтирования, время тика по детекторам, счётчики
событий/действий, освобождённые байты, размер блоклиста, состояние сенсоров up/down и другое.
`/health` возвращает 503, если heartbeat быстрого планировщика устарел (тот же
сигнал, что управляет systemd watchdog). Warden также профилирует себя:
`warden_module_cpu_seconds_total`, `warden_module_heap_bytes`,
`warden_thread_cpu_seconds_total`, `warden_self_cgroup_memory_bytes{kind=anon|page_cache|kernel}`
— см. [docs/performance.md](docs/performance.md) о стоимости каждого модуля. Каждое событие и результат действия
также пишутся как JSON в `/var/log/warden/events.jsonl` (с ротацией).

## Структура проекта

```
crates/
  warden-core/      конфигурация · события · действия · политика · гистерезис · rate limits   (чистые, без I/O)
  warden-sys/       PSI · procfs · pidfd · cgroup v2 · kmsg · netlink · fanotify · nftables
  warden-detect/    детекторы · сенсоры · FIM (сигнатуры + корреляция) · ModSecurity · health-проверки ·
                    советник по тюнингу · эвристики · планировщик
  warden-respond/   безопасные действия: kill · stop · throttle · cgroup · лимиты юнитов · карантин · очистка ·
                    фаервол · sysctl · снимок
  wardend/          демон: движок · журнал событий · уведомления · серверы управления + метрик
  wardenctl/        CLI управления + офлайн-диагностика
config/             эталонный warden.toml, профили conf.d (webserver, database, workstation), примеры сигнатур
packaging/          systemd-юнит, шаблон nftables, скрипты maintainer'а deb
scripts/            install.sh · uninstall.sh · build-deb.sh [--portable] · check-seccomp.sh · check-glibc.sh ·
                    test-deb-install.sh
fuzz/               цели cargo-fuzz для каждого парсера недоверенного ввода (тела в crates/warden-fuzz)
bench/              profile.py (матрица CPU/I/O/RAM по модулям) · dhat_modules.py (heap по модулям)
docs/               архитектура · детекторы · интеграции (веб-стеки, ModSecurity, БД, контейнеры) · безопасность ·
                    события (каталог каждого события) · производительность (измеренная стоимость каждого модуля) ·
                    reviews/ (отчёты код-ревью и аудита, на русском)
```

## Сборка и тестирование

```bash
cargo build --release --workspace
cargo test  --workspace        # юнит-тесты; некоторые требуют root (procfs/pidfd/fanotify) — запускайте с sudo
sudo cargo test --workspace    # включает end-to-end тест демона
cargo clippy --workspace --all-targets -- -D warnings
sudo ./scripts/check-seccomp.sh   # юнит разрешает каждый syscall и семейство сокетов, используемые демоном
sudo cargo llvm-cov --workspace   # покрытие строк (CI floor: .github/coverage-floor)
cd fuzz && cargo +nightly fuzz run access_log   # libFuzzer; `cargo test -p warden-fuzz` — стабильный smoke-прогон
./scripts/build-deb.sh --portable # релизный пакет (слинкован в контейнере Ubuntu 22.04)
```

CI дополнительно устанавливает настоящий systemd-юнит на свежей Ubuntu 24.04 VM,
запускает его, проверяет, что он остаётся вверх без перезапусков или core dump'ов, и заставляет его
поймать веб-шелл — класс отказа, который юнит-тесты увидеть не могут. Он собирает
`.deb` на Ubuntu 22.04 и устанавливает и запускает его в чистых Debian 12,
Ubuntu 22.04 и 24.04 контейнерах; измеряет покрытие на каждый push и pull
request (сводка задания и комментарий к PR; сборка падает ниже порога или
когда покрытие падает более чем на полпункта относительно main); и фаззит каждый
парсер недоверенного ввода по минуте на цель.

Набор тестов обширен и намеренно упражняет реальные интерфейсы ядра
(разбирает живой `/proc`, открывает pidfd, регистрирует PSI-триггеры и метки fanotify),
а не только моки, плюс полный end-to-end тест, который загружает
бинарник `wardend` и обрушивает на него реальные инциденты.

## Совместимость

| функция | требует | без этого |
|---|---|---|
| бинарники | glibc 2.34+ (Debian 12, Ubuntu 22.04, RHEL 9 и новее) | — |
| давление PSI и триггеры | Linux 4.20+, `CONFIG_PSI=y` (загрузка `psi=1` на RHEL) | обнаружение давления деградировано |
| kill без гонок | pidfd (Linux 5.3+) | откат к перепроверке времени старта |
| события процессов в реальном времени | proc connector + `CAP_NET_ADMIN` (события fork фильтруются в ядре на 6.6+) | откат к периодическим сканам `/proc` |
| обнаружение SUID/SGID в реальном времени | fanotify `FAN_REPORT_DFID_NAME` (Linux 5.9+), `CAP_SYS_ADMIN` + `CAP_DAC_READ_SEARCH` | только периодический обход |
| мгновенные оповещения об упавших юнитах | systemd + system D-Bus | опрос `systemctl` каждые `systemd.interval` |
| веб-FIM в реальном времени | fanotify + `CAP_SYS_ADMIN` | откат к запланированным сканам |
| заморозка/kill сервиса | cgroup v2 | эти действия недоступны |
| блокировка IP | `nft` | действия блокировки падают (сообщается) |
| события аутентификации, vacuum журнала | systemd/journalctl (иначе auth.log) | читает файл лога вместо этого |
| корреляция WAF | ModSecurity v2 или v3, пишущий журнал аудита или ошибок | — |
| карантин файлов `chattr +i` | `CAP_LINUX_IMMUTABLE` (выдаётся юнитом) | карантин падает с EPERM (сообщается) |

Запустите `wardenctl doctor` на любом хосте для окончательного отчёта.

## Лицензия

MIT — см. [LICENSE](LICENSE).

> ⚠️ **Бета.** Warden выполняет деструктивные действия в вашей системе. Начните с
> `dry_run = true` (по умолчанию), просмотрите, что он сделал бы, и держите бюджеты
> автоматических выключателей консервативными, пока не доверитесь ему в вашей среде.
