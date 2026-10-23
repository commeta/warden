# Детекторы и справочник событий

У каждого события есть точечный `kind`, важность, субъект и структурированные детали.
Это каталог того, что порождает Warden, и конфигурации, которая этим управляет.
`[section]` относится к `warden.toml`. Поля `details` каждого события
и формат журнала — в [events.md](events.md).

## Стабильность

| kind | важность | триггер | конфиг | действие по умолчанию |
|---|---|---|---|---|
| `memory.pressure` | warning→critical | PSI memory full avg10, `MemAvailable`, использование свопа, удержанное сверх `sustain`. `top_cgroups` ранжируется по памяти, которую cgroup *закрепляет* (anon + shmem + невытесняемая память ядра), и показывает page cache / освобождаемое отдельно | `[memory]` | `on_critical` (snapshot, kill худшего виновника) |
| `memory.swap_storm` | critical | устойчивая подкачка (pswpin/out + major faults) с высоким PSI full — «долгий свопинг / сервер висит» | `[memory.swap_storm]` | snapshot, kill |
| `memory.kill_ineffective` | warning | kill по памяти не поднял `MemAvailable` хотя бы на половину того, что держала жертва (анонимная память + своп — то, что считает ранжирование виновников): память держится tmpfs/разделяемой памятью/ядровым slab, и kill'ы прекращаются до конца эпизода. Удачные kill'ы ограничены `max_kills_per_episode` (3) | `[memory]` | — |
| `memory.oom_kill` / `kernel.oom_kill` | warning | сработал OOM-killer ядра; называет сервис/контейнер, когда исчерпан его собственный лимит cgroup | `[kernel] on_oom_kill` | snapshot |
| `cpu.pressure` | warning→critical | PSI cpu avg60, нагрузка/CPU, iowait, задачи в D-состоянии | `[cpu]` | `on_critical` |
| `cpu.fork_storm` | warning | скорость создания процессов (fork-бомба) | `[cpu] fork_rate_warning` | — |
| `process.cpu_hog` | warning | один процесс ≥`hog_percent` в течение `hog_duration` | `[cpu]` | — |
| `io.pressure` | warning→critical | PSI io full avg10; называет топ процессов по I/O | `[io]` | `on_critical` |
| `system.stall` | warning→critical | собственный планировщик демона проснулся поздно (зависание всего хоста) | `[stall]` | snapshot |
| `disk.space` | warning→critical | использование файловой системы; перечисляет удалённые-но-открытые файлы и самые большие файлы (собираются за 1 с, чтобы алерт и его очистка не ждали; `largest_files_partial`, когда оборвано). Напоминания с back-off'ом (15м, 30м, 1ч … 24ч), если использование не выросло на пункт; запуск очистки, освободивший < 1% (минимум 256 МиБ), ставит плейбук на паузу с тем же backoff'ом (`cleanup_skipped`); эта история сохраняется в `disk-cleanups.json`, так что рестарт или reload не повторяет бесполезную очистку. Плейбук ходит по дескрипторам каталогов и никогда не идёт по симлинку ниже корня (каталог, подменённый на симлинк во время обхода, не может перенаправить удаление); шаг `/tmp` по умолчанию стареет файлы как `systemd-tmpfiles` (`age_from = "newest"`: самая свежая из atime/mtime/ctime) и пропускает каталоги `PrivateTmp`, X-блокировки и сокеты (`exclude`) | `[disk]` | плейбук `cleanup` |
| `disk.usage_report` | notice | «кто занимает диск»: очистка освободила (почти) ничего, или у критической точки монтирования нечего чистить (критическая точка монтирования запускает обход сразу) → ограниченный фоновый `du -x` (одна файловая система, idle-приоритет I/O, с пейсингом по давлению I/O — `[daemon.pacing]`, память ограничена, каким бы ни было дерево, `usage_report_max_entries` / `usage_report_max_time`): самые большие каталоги на двух уровнях, самые большие файлы, `not_found_by_walk` (удалённые-но-открытые файлы, данные под точками монтирования, снапшоты). Не чаще раза в сутки на точку монтирования (`usage_report_every`); последующие напоминания `disk.space` несут `biggest_dirs` | `[disk]` | — |
| `disk.inodes` | warning→critical | исчерпание inode'ов | `[disk]` | — |
| `disk.readonly` | critical | rw-файловая система перемонтирована в read-only (ошибки I/O) | `[disk]` | snapshot |
| `disk.fill_prediction` | warning | линейная проекция говорит, что точка монтирования заполнится в пределах `horizon` | `[disk]` | — |
| `limits.file_handles` / `.pids` / `.conntrack` | warning→critical | системные ресурсные лимиты | `[limits]` | рост `sysctl` при `[tuning] auto_grow` |
| `limits.process_fds` | warning | один процесс близок к своему `RLIMIT_NOFILE` | `[limits]` | — |
| `network.listen_overflow` / `.syn_flood` / `.retransmits` / `.iface_errors` | warning | счётчики TCP/интерфейса | `[network]` | — |
| `process.zombies` / `.uninterruptible` | warning | накопление зомби / долгое D-состояние | `[limits]`, `[process]` | — |
| `systemd.unit_failed` | warning→critical | юнит вошёл в `failed` — мгновенно через D-Bus (`detected_by: dbus`), или опросом `systemctl` каждые `interval`, когда системная шина недоступна (`detected_by: systemctl`); critical, когда бюджет авто-рестартов исчерпан. Восстановление (`info` + `resolved`) сообщается, когда юнит устаканился (`active`, `inactive`, `reloading`); упавший юнит, который лишь снова запускается (таймер, авто-рестарт), остаётся failed до конца этого прогона | `[systemd]` | опциональный `restart_unit` |
| `health.down` | critical | проба HTTP/TCP/командой провалилась `failures` раз подряд (зависший сервис) | `[[health.check]]` | snapshot + `restart_unit`, когда задан `unit` |
| `process.limit_exceeded` | warning | правило `[[process.limit]]`: устойчивый CPU, время жизни или RSS выше лимита | `[[process.limit]]` | на правило (`throttle`, `kill`, `limit_unit`…) |
| `tuning.advice` | notice | sysctl или настройка ядра не подходит железу или нагрузке | `[tuning]` | нет (совет); ёмкостные лимиты растут с `auto_grow` |
| `waf.hit` | info | ModSecurity заблокировала запрос (≤1 событие на IP в минуту) | `[waf]` | — |
| `hardware.memory_corrected` / `_uncorrected` | warning / critical | ошибки ECC EDAC | `[hardware]` | — |
| `hardware.temperature` | warning→critical | термозоны | `[hardware]` | — |
| `system.clock_unsynchronized` | warning | 15 минут: флаг синхронизации ядра выключен (то, что показывает `timedatectl`) или оценка ошибки NTP-демона превышает `clock_max_error`. `maxerror` ядра экспортируется только как метрика: оно растёт на 500 мкс/с между опросами NTP на здоровых хостах | `[hardware]` | — |
| `kernel.*` | notice→critical | `/dev/kmsg`: oops, hung task, soft/hard lockup, RCU stall, ошибки fs/io, MCE, conntrack-full… | `[kernel]` | на правило |
| `kernel.taint` / `security.kernel_module_loaded` | warning | флаги taint изменились / загружен модуль | `[kernel]` | — |

## Вторжения и целостность

| kind | важность | триггер | действие по умолчанию |
|---|---|---|---|
| `security.privilege_escalation` | critical | root-процесс, чей не-root-родитель не является известным брокером; `setuid(0)` программой, никогда не имевшей root | stop, snapshot |
| `security.unknown_suid_exec` | critical | euid 0 для не-root-пользователя через SUID-бинарник, которого нет в allowlist | stop |
| `security.fileless_exec` | critical | запуск из `memfd:` или из образа, удалённого из записываемого места (`/tmp`, `/dev/shm`, home, корни сайтов). Контейнерные рантаймы (runc, crun, …) законно переисполняются из memfd: это освобождается, только когда образ рантайма запущен доверенным системным бинарником (или рантаймом того же пользователя), никогда из-за имени | stop |
| `process.stale_binary` | notice | бинарник заменён на диске (обновление пакета), пока процесс работает со старым; подсказка называет юнит для перезапуска | — |
| `process.deleted_binary` | warning | бинарник удалён из системного пути и не заменён | — |
| `security.reverse_shell` | critical | shell с stdin/stdout на TCP-сокете | kill |
| `security.miner` / `security.miner_port` | critical / warning | известные имена майнеров, или загрузка CPU + порт майнинг-пула | kill |
| `security.masquerade` | critical | пользовательский процесс, замаскированный под поток `[kernel]` (системный бинарник под root, чьё имя лишь напоминает одно из них, вроде `/usr/sbin/watchdog`, не сообщается) | — |
| `security.web_spawn` | warning→critical | веб-воркер (php-fpm/node/…, не-root) породил shell или инструмент; critical при красных флагах загрузчика/reverse shell | kill (при красных флагах) |
| `security.db_spawn` | warning→critical | сервер БД (mysqld, postgres, redis…) породил shell или инструмент — SQLi→RCE | kill (при красных флагах) |
| `security.waf_attack` | warning | один IP заблокирован ModSecurity `block_after` раз в пределах `window` | block_ip |
| `security.exec_from_writable` | notice→critical | запуск бинарника/скрипта из записываемого/upload-каталога | — |
| `security.ld_preload` | warning | привилегированный/веб-процесс с подозрительным `LD_PRELOAD` | — |
| `security.ptrace` | notice→warning | не-отладчик присоединился через ptrace (инъекция кода) | — |
| `security.new_lineage` | notice | сервис/веб-учётная запись запустила программу, никогда не виденную во время обучения | — |
| `security.ssh_bruteforce` | warning | повторяющиеся SSH-неудачи аутентификации с одного IP | block_ip |
| `security.bruteforce_success` | critical | успешный логин после всплеска неудач | — |
| `security.web_user_sudo` | critical | веб-учётная запись использовала sudo | — |
| `auth.root_login` / `auth.sudo_failure` / `auth.privileged_group` / `auth.account_created` … | info→critical | события auth-log/journald | — |
| `security.uid0_account` | critical | появилась новая учётная запись с uid 0 | — |
| `security.webshell` | warning→critical | сигнатуры пометили файл сайта (оценка ≥ `fim.alert_score`) | quarantine, restart пула |
| `security.malicious_writer` | critical | веб-воркер, записавший помеченный файл; при массовом изменении (`fim.mass_change`) — только писатели, чьи собственные записи в окне совпали с сигнатурами; всплеск чистых изменений (обновление CMS) никого не убивает | kill |
| `security.webshell_access` | critical | запрос попал в помеченный файл (кто-то использует шелл) | block_ip |
| `security.new_suid` | info→critical | новый SUID/SGID-файл: в реальном времени через метки файловой системы fanotify (`detected_by: real time (fanotify)`), или обходом (`integrity.suid_rescan`, после переполнения, на ядрах без `FAN_REPORT_DFID_NAME`). Critical в записываемых местах, info, когда файл подтверждён dpkg | — |
| `security.binary_replaced` / `security.sudoers_changed` / `security.persistence_*` / `security.ssh_key_added` / `security.ld_so_preload` | notice→critical | изменения baseline критических файлов | — |
| `security.new_listener` / `security.bind_shell` | notice→critical | новый слушающий сокет (шеллоподобные ⇒ critical) | — |
| `security.lsm_disabled` | critical | AppArmor выключен / SELinux → permissive во время работы | — |
| `heuristics.suspicious` / `heuristics.contain` / `heuristics.ip_threshold` | warning→critical | накопленная подозрительность перешла порог | `on_contain` / block_ip |

### Как анализируются exec-события

Каждый `exec` на хосте (proc connector) анализируется по правилам
выше. Сочетание (имя и uid родителя, исполняемый файл, uid ребёнка), прошедшее
полный анализ три раза, идёт **быстрым путём** (`process.exec_fast_path`):
одно чтение `/proc/<pid>/status` и readlink `exe`, родитель из кеша.
Быстрый путь всё равно проверяет скрипты, запускаемые из записываемых мест (оболочки
и интерпретаторы, каждый exec), и LD_PRELOAD root-процессов (каждый четвёртый
exec), и каждый `process.exec_recheck_every`-й exec (16-й) всё равно получает полный
анализ. Сочетания с веб- или СУБД-родителем, веб-пользователем,
сменой uid (sudo/su/setuid-бинарники), удалённым, memfd- или записываемым
исполняемым файлом или именем «под поток ядра» всегда анализируются полностью, и
находка сбрасывает сочетание. Задайте `exec_fast_path = false`, чтобы анализировать
каждый exec полностью.

## Эвристический скоринг

Каждая находка `security.*` добавляет очки (`[heuristics.weights]`) процессу-субъекту
и/или IP. Оценки затухают с периодом полураспада (`half_life`). Процесс, перешедший
`alert_score`, поднимает `heuristics.suspicious`; перешедший `contain_score` —
поднимает `heuristics.contain` (который несёт `on_contain`, по умолчанию stop+snapshot).
Половина веса каждой находки также течёт к родителю, так что воркер, который продолжает
порождать подозрительных детей, сам становится целью. Смотрите живые оценки через
`wardenctl scores`.

IP, перешедший `ip_block_score`, поднимает `heuristics.ip_threshold` с
`block_ip` — если только находка, перешедшая его, не пришла от источника, который
намеренно не блокирует: `auth.ssh_block = false`, `waf.block = false`,
`fim.block_attackers = false`, адрес из allowlist, или `[[policy]]`, которая
сделала событие `alert_only` или отняла у него `block_ip`. Такие события несут
`ip_block_off` (причину) и всё равно идут в оценку адреса, так что более поздняя
находка от источника, который блокирует, может запустить блокировку со всеми
доказательствами. Чтобы не блокировать адреса вообще никогда: `[actions.firewall] enabled =
false` (`block_ip` тогда получает отказ).

## Тюнинг без правки основного конфига

Используйте правила `[[policy]]` (см. эталонный конфиг), чтобы заглушить заведомо
безопасный паттерн, понизить шумный детектор до alert-only или добавить более сильное действие на
конкретный субъект — всё, не трогая пороги детекторов. Прогоните день в
`dry_run = true` (по умолчанию), просмотрите `wardenctl events`, напишите политики для
ложных срабатываний, затем включите действия.
