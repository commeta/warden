# Каталог событий

Всё, что замечает Warden, — это **событие**; всё, что он делает, сообщается как
событие. Эта страница перечисляет каждый `kind`, который демон может порождать, с его обычной
важностью и триггером. Триггеры, пороги и действия по умолчанию
основных детекторов объяснены в [detectors.md](detectors.md); настройки —
в эталонном [`config/warden.toml`](../config/warden.toml).

## Анатомия

Один JSON-объект на строку в `events.path` (по умолчанию
`/var/log/warden/events.jsonl`), тот же объект в `wardenctl events --json`
и в `WARDEN_EVENT_JSON`:

| поле | смысл |
|---|---|
| `id` | уникальный и возрастающий, в том числе между рестартами (`wardenctl events --since-id N`) |
| `ts_ms` | Unix-время, миллисекунды |
| `kind` | точечное имя из таблиц ниже |
| `severity` | `info` < `notice` < `warning` < `critical` < `emergency` |
| `title` | одна строка для человека |
| `subject` | о чём событие: `system`, `process`, `file`, `mount`, `unit`, `ip`, `user` или `cgroup`. Действия разрешаются относительно него (`kill` убивает процесс-субъект, `block_ip` блокирует адрес-субъект, …) |
| `source` | детектор, который его породил |
| `fingerprint` | ключ дедупликации: одинаковый fingerprint в пределах cooldown сообщается один раз. Его первый сегмент — это `kind` события; условие сообщается как `kind[:detail]:<severity>` (`cpu.pressure:warning`, `disk.space:/:critical`, `process.cpu_hog:812:9731:warning`) и закрывается как `kind[:detail]:resolved`. Закрытие завершает эпизод `X` и всех `X:…`, так что вернувшееся условие сообщается снова сразу, как и следующее закрытие. Канал-нотификатор получает закрытие, только если получал условие |
| `details` | структурированные факты (`exe`, `cmdline`, `parent`, `cgroup`, `ip`, …). `policy` перечисляет совпавшие правила `[[policy]]`; `ip_block_off` говорит, почему событие об адресе его не блокирует (например, `"auth.ssh_block = false"`, `"policy office NAT"`) — тогда эвристики тоже по нему не блокируют; `actions_withheld` говорит, почему действия события были намеренно отозваны (`"process.act_on_existing = false"`, `"policy #2 (alert_only)"`) — событие всё равно идёт в оценку подозрительности процесса, но не может заставить эвристики изолировать процесс |
| `actions` | что запросил детектор; результат приходит следом событиями `action.*` |
| `resolved` | `true` на событии «вернулось в норму» для условия |

**Условия.** Всё, что сообщает состояние — уровень выше порога,
процесс выше лимита, точка монтирования ушла в read-only — имеет один жизненный цикл: оно
сообщается, когда начинается (с его действиями), напоминается с экспоненциальным
back-off'ом, пока держится (`reminder`, `next_reminder_in`: первый через
`repeat` или 10 минут, затем с удвоением, не чаще раза в сутки), сообщается сразу, когда
меняется его важность, и закрывается, когда останавливается (`info` + `resolved`,
`lasted_seconds`). Закрытие с `closed_by: reload` было отправлено потому, что
reload выключил детектор, наблюдавший за условием, а не потому, что
оно исчезло.

Субъекты-процессы несут PID **и** время старта; каждое действие перепроверяет
и то, и другое, так что переиспользованный PID никогда не затрагивается.

## Хуки: события в ваших собственных скриптах

И `exec`-действие, и нотификатор `[[notify.command]]` запускают программу
с событием в окружении (нотификатор получает его так, как позволяет `notify.details`
— по умолчанию секреты маскируются, см. [security](security.md); `exec`-хук получает оригинал):

| переменная | содержимое |
|---|---|
| `WARDEN_EVENT_JSON` | всё событие (без `details`, если они не помещаются в одну строку окружения, ~100 КБ) |
| `WARDEN_EVENT_KIND` | `kind` |
| `WARDEN_SEVERITY` | `severity` |
| `WARDEN_SUBJECT` | `subject` текстом, например `process php-fpm8.3[4012] user=www-data` |
| `WARDEN_TITLE` | `title` |

Хук работает от root с capability демона, если вы не дадите ему
учётную запись: `user = "…"` на `exec`-действии, нотификаторе или командной проверке
здоровья, или `daemon.command_user` для всех них — для этого пакет создаёт
системного пользователя `_warden`; `user = "root"` на конкретном элементе оставляет один хук
привилегированным. Переключение происходит в дочернем процессе перед `exec`
(дополнительные группы, gid, uid) и сбрасывает все capability; программа
получает `HOME`, `USER`, `LOGNAME` этого пользователя и `/` как рабочий каталог, так что
она должна быть читаема и исполняема этим пользователем. Неизвестный пользователь проваливает
хук (никогда не откатывается к root); `wardend --check-config` предупреждает об этом.
Каждый хук — лидер своей группы процессов, и его таймаут убивает
всю группу — то, что он запустил в фоне, умирает с ним. У `exec`-действия
нет stdin; команда-нотификатор получает текст сообщения на stdin. То, что хук печатает,
читается параллельно и ограничено (64 КиБ для `exec`, из которых первые 500 символов stdout идут в
результат `action.exec`; 4 КиБ для нотификаторов), так что болтливый хук или дочерний процесс, держащий
пайпы открытыми, не может заблокировать демон.

## Как читать таблицы

*Важность* — обычная; где показан диапазон, детектор выбирает по тому,
насколько плохо условие. Детекторы включаются в своём `[section]` из
`warden.toml`; `kind` никогда не появляется, когда его детектор выключен.

## Стабильность

| kind | важность | когда |
|---|---|---|
| `memory.pressure` | warning → critical | простой PSI памяти, низкий `MemAvailable` или использование свопа, удержание сверх `sustain`; называет виновника (RSS, его анонимную часть, своп) и топ cgroups. `kill_withheld` говорит, почему kill был отозван (неэффективный kill ранее в эпизоде, или достигнут `max_kills_per_episode`) |
| `memory.swap_storm` | critical | устойчивая подкачка с высоким PSI full: ситуация «сервер висит и свопит» (тот же `kill_withheld`) |
| `memory.kill_ineffective` | warning | жертву убили, но MemAvailable вырос меньше, чем на половину того, что она держала (`expected`, `freed`): память держится где-то ещё — `shmem` (tmpfs, разделяемая память), `slab_unreclaimable` — и kill'ы прекращаются до конца эпизода; `hint` говорит, где искать |
| `memory.oom_kill` | warning | сработал OOM-killer ядра (счётчик сдвинулся) |
| `cpu.pressure` | warning → critical | PSI cpu, нагрузка на CPU, iowait или задачи в D-состоянии |
| `cpu.fork_storm` | warning | частота fork выше `fork_rate_warning` |
| `io.pressure` | warning → critical | PSI io full; называет топ процессов по I/O |
| `process.cpu_hog` | warning | один процесс выше `hog_percent` в течение `hog_duration`; закрывается, когда он успокаивается или выходит |
| `process.limit_exceeded` | warning | правило `[[process.limit]]`: устойчивый CPU, время жизни или RSS; одно условие на правило и процесс, закрывается, когда возвращается в пределы лимита |
| `process.zombies` | warning | накопление зомби; закрывается при снижении ниже `zombies_warning` |
| `process.uninterruptible` | warning | долгое D-состояние; закрывается, когда процесс из него выходит |
| `limits.process_fds` | warning | один процесс близок к своему `RLIMIT_NOFILE`; закрывается, когда уже нет |
| `limits.file_handles`, `limits.pids`, `limits.conntrack` | warning → critical | системный лимит почти исчерпан; `[tuning] auto_grow` может его поднять |
| `system.stall` | warning → critical | собственный высокоприоритетный планировщик Warden проснулся поздно: весь хост был заморожен |
| `system.clock_unsynchronized` | warning | 15 минут часы не синхронизированы (флаг ядра или оценка ошибки); `info`, когда снова да |
| `warden.slow_detector` | notice | детектор работал необычно долго (его имя и длительность в заголовке) |
| `warden.worker_panic` | warning | поток демона (исполнитель, нотификатор, сенсор) запаниковал; он был перезапущен, а сбойный элемент пропущен |

## Диск

| kind | важность | когда |
|---|---|---|
| `disk.space` | warning → critical | использование выше порогов; `info` + `resolved`, когда вернулось в норму. Несёт `deleted_but_open` и `largest_files` (`largest_files_partial`, когда 1-секундный бюджет оборвал обход); напоминания с back-off'ом |
| `disk.inodes` | warning → critical | исчерпание inode'ов; ступенчато снижается, напоминает с back-off'ом и закрывается как `disk.space` |
| `disk.readonly` | notice / critical | **critical**: файловая система ушла в read-only под наблюдением (ошибки I/O или файловой системы), со снимком; **notice**: она уже была такой при первом взгляде (старт). `info` + `resolved`, когда снова записываема |
| `disk.fill_prediction` | warning | точка монтирования заполнится в пределах `horizon` при текущей скорости |
| `disk.usage_report` | notice | «кто занимает диск»: ограниченный фоновый обход, запускается сразу для критической точки монтирования и после любой очистки, освободившей ноль |

## Железо и ядро

| kind | важность | когда |
|---|---|---|
| `hardware.memory_corrected` | warning | EDAC: исправленные ошибки ECC |
| `hardware.memory_uncorrected` | critical | EDAC: неисправимые ошибки ECC |
| `hardware.temperature` | warning → critical | термозона выше своего порога; `info`, когда снова норма |
| `hardware.thermal_throttle` | warning | в логе ядра сказано, что частота CPU была урезана |
| `hardware.mce` | warning | machine-check events |
| `kernel.oom_kill` | warning | лог ядра сообщает об OOM-kill; называет cgroup, чей лимит был исчерпан |
| `kernel.hung_task` | warning | «заблокирован более чем на N секунд» |
| `kernel.soft_lockup`, `kernel.hard_lockup` | critical | зависания CPU |
| `kernel.rcu_stall` | warning | обнаружен RCU stall |
| `kernel.oops` | critical | oops, BUG, general protection fault, panic |
| `kernel.fs_error` | critical | ошибки ext4/XFS/btrfs/F2FS |
| `kernel.io_error` | warning | ошибки блочного устройства или NVMe/ATA (устройство в `details`) |
| `kernel.segfault` | info | пользовательский процесс получил segfault |
| `kernel.segfault_burst` | warning | одна и та же программа упала несколько раз за 5 минут |
| `kernel.unsigned_module`, `kernel.out_of_tree_module` | warning / notice | сообщения о подписи модуля или его «вне дерева» |
| `kernel.taint` | warning → critical | флаги taint ядра изменились (critical для принудительного модуля, machine check, bad page, live patch…) |
| `network.conntrack_full` | critical | «nf_conntrack: table full, dropping packet» |
| `network.syn_flood_kernel` | warning | ядро залогировало «Possible SYN flooding» |
| `network.link_down`, `network.link_up` | warning / info + `resolved` | изменения состояния линка, один раз на изменение и интерфейс (flap сообщается полностью); fingerprint `network.link:<iface>`, `:resolved` для «up» |
| `network.listen_overflow` | warning | переполняются очереди accept; закрывается |
| `network.syn_flood` | warning | SYN-cookies используются на высокой частоте; закрывается |
| `network.retransmits` | warning | TCP-ретрансмиссии выше порога; закрывается |
| `network.iface_errors` | warning | ошибки и дропы интерфейса в секунду; закрывается, в том числе когда интерфейс исчезает (его счётчики и серии метрик удаляются) |
| `lsm.apparmor_denied`, `lsm.selinux_denied` | info | отказы в доступе |
| `lsm.denial_burst` | warning | много отказов одной и той же программы за короткое время |
| `tuning.advice` | notice | sysctl или настройка ядра не подходит железу или нагрузке (`wardenctl tuning`) |

## Сервисы

| kind | важность | когда |
|---|---|---|
| `systemd.unit_failed` | warning → critical | юнит вошёл в `failed`, сообщается сразу через D-Bus; для юнитов из `auto_restart` с действием `restart_unit` — решает бюджет рестартов responder'а на юнит (`max_restarts_per_hour`, списывается только за реально выполненные рестарты); critical, когда юнит падал чаще этого в течение часа |
| `health.down` | critical | проба `[[health.check]]` провалилась `failures` раз подряд; `info` + `resolved`, когда восстановилась |

## Вторжение

| kind | важность | когда |
|---|---|---|
| `security.privilege_escalation` | critical | root-процесс от не-root-родителя, не являющегося известным брокером; `setuid(0)` программой, никогда не имевшей root |
| `security.unknown_suid_exec` | critical | euid 0 для не-root-пользователя через SUID-бинарник, который не разрешён |
| `security.fileless_exec` | critical | код запускается из `memfd:` или из образа, удалённого из записываемого места. memfd контейнерного рантайма принимается, только если его запустил системный бинарник рантайма |
| `security.reverse_shell` | critical | shell с stdin/stdout на TCP-сокете |
| `security.bind_shell`, `security.new_listener` | critical / notice | новый слушающий сокет; шеллоподобные — critical |
| `security.miner`, `security.miner_port` | critical / warning | известное имя майнера, или загрузка CPU плюс порт майнинг-пула |
| `security.masquerade` | critical | процесс, замаскированный под поток `[kernel]` |
| `security.web_spawn` | warning → critical | веб-воркер породил shell или инструмент; critical при флагах загрузчика или reverse shell |
| `security.db_spawn` | warning → critical | сервер БД породил shell или инструмент |
| `security.exec_from_writable` | notice → critical | программа запущена из записываемого или upload-каталога |
| `security.ld_preload` | warning | привилегированный или веб-процесс с подозрительным `LD_PRELOAD` |
| `security.ptrace` | notice → warning | не-отладчик присоединился через ptrace |
| `security.new_lineage` | notice | сервис или веб-учётная запись запустила программу, никогда не виденную во время обучения |
| `process.stale_binary` | notice | бинарник заменён на диске (обновление пакета), пока процесс работает со старым; подсказка называет юнит для перезапуска |
| `process.deleted_binary` | warning | бинарник удалён из системного пути и не заменён |
| `security.webshell` | warning → critical | сигнатуры пометили файл сайта (оценка на уровне `fim.alert_score` или выше) |
| `security.malicious_writer` | critical | веб-воркер, записавший помеченный файл |
| `security.webshell_access` | critical | запрос попал в помеченный файл: кто-то использует шелл |
| `security.waf_attack` | warning | один IP заблокирован ModSecurity `block_after` раз в пределах `window` |
| `waf.hit` | info | ModSecurity заблокировала запрос (не более одного события на IP в минуту) |
| `security.kernel_lockdown_violation` | warning | kernel lockdown отказал в чём-то |
| `security.kernel_module_loaded` | notice | загружен модуль ядра |
| `security.lsm_disabled` | critical | AppArmor выключен, или SELinux перешёл в permissive, во время работы |
| `security.lsm_profiles_unloaded` | warning | число профилей AppArmor в режиме enforce упало |
| `heuristics.suspicious` | warning | накопленная оценка подозрительности процесса перешла `alert_score`; `containment_withheld`, когда она также перешла `contain_score` по доказательствам с отозванными действиями (`actions_withheld`) |
| `heuristics.contain` | critical | … перешла `contain_score`; несёт `on_contain` |
| `heuristics.ip_threshold` | warning | то же для удалённого адреса |

## Аутентификация

Источник journald принимает строку, только если отправитель заверен ядром
(root или системный бинарник, совпадающий с именем программы); `logger -t sshd`
от непривилегированного пользователя считается в `warden_auth_untrusted_lines_total`
и игнорируется. Источник-файл `auth.log` не различает отправителей.

| kind | важность | когда |
|---|---|---|
| `security.ssh_bruteforce` | warning | повторяющиеся SSH-неудачи с одного адреса; блокирует его через `block_ip`, если он не в allowlist |
| `security.bruteforce_success` | critical | логин успешен с адреса после всплеска неудач |
| `auth.root_login` | warning | root вошёл по SSH (`alert_root_login`) |
| `auth.login` | info | вход по SSH |
| `auth.sudo` | info | команда `sudo` |
| `auth.sudo_failure` | warning / critical | неудачи sudo; critical для веб-учётной записи |
| `security.web_user_sudo` | critical | веб-учётная запись использовала `sudo` |
| `auth.su_failure` | warning | неудача аутентификации `su` |
| `auth.account_created` | warning | создана учётная запись пользователя |
| `security.uid0_account` | critical | новая учётная запись с uid 0 |
| `auth.privileged_group` | warning | пользователь добавлен в `sudo`, `wheel`, `docker`, … |
| `auth.account_deleted` | notice | учётная запись пользователя удалена |
| `auth.password_changed` | notice | сменился пароль |

## Целостность

| kind | важность | когда |
|---|---|---|
| `integrity.baseline_created` | info | снят baseline системных файлов (первый старт) |
| `integrity.file_changed` | notice → warning | отслеживаемый файл изменился |
| `integrity.accounts_changed` | notice | изменились `/etc/passwd`, `group`, `shadow`, `gshadow` |
| `security.binary_replaced` | critical | изменились `sudo`, `sshd`, `passwd`, `login` или `su` |
| `security.sudoers_changed` | warning | изменились `sudoers` или `sudoers.d` |
| `security.ssh_keys_changed`, `security.ssh_key_added` | warning | изменился `authorized_keys` или в него добавлен ключ |
| `security.pam_changed` | warning | изменилась конфигурация PAM |
| `security.ld_so_preload` | critical | появился или изменился `/etc/ld.so.preload` |
| `security.persistence_cron`, `security.persistence_systemd`, `security.persistence_shell`, `security.persistence_system` | warning | изменились места автозапуска: cron, юниты systemd, профили shell, другие системные хуки |
| `integrity.suid_baseline` | info | снят baseline SUID/SGID |
| `security.new_suid` | info → critical | новый SUID/SGID-файл, в реальном времени через fanotify или периодическим обходом |
| `fim.baseline_created` | info | снят baseline веб-сайта |
| `fim.changed` | notice | файл сайта изменился (с писателем, когда он известен) |
| `fim.changes` | notice | сводка изменений, найденных сканом |
| `fim.mass_change` | warning → emergency | `burst_files` изменений в пределах `burst_window`. **emergency** только когда изменения в окне совпали с сигнатурами (`malicious_content: true`, `malicious_writers`): инфекция распространяется, и только те писатели убиваются (`kill_writer`). Без вредоносного содержимого — **warning**, как выглядит обновление CMS или плагина, с `hint` поставить FIM на паузу вокруг обновлений (`wardenctl fim pause <site> 30m`) |
| `fim.deleted` | notice | файлы сайта были удалены |
| `fim.world_writable` | warning | скриптовые файлы стали доступны на запись всем |

## Что сделал Warden

Каждое действие, которое было выполнено, отклонено или пропущено, сообщается как событие
kind `action.<name>`: субъект исходного события, `details.status`
(`done`, `dry_run`, `skipped` — cooldown или rate limit, `refused` — защищённая
цель или бюджет — или `failed`), `details.cause_id` / `cause_kind` / `cause`
указывают на событие, которое его запросило, а для очисток — `details.freed_bytes`.
Важность следует за исходом: `warning` для реального изменения или отказа,
`notice` для dry-run, отказа или очистки, ничего не нашедшей, `info`
для снимка или пропуска.

`<name>` — одно из `snapshot`, `kill`, `stop`, `freeze_cgroup`, `kill_cgroup`,
`restart_unit`, `quarantine`, `block_ip`, `journal_vacuum`, `delete_old`,
`truncate_large`, `truncate_deleted`, `apt_clean`, `throttle`, `limit_unit`,
`sysctl`, `exec`.

Сам демон сообщает:

| kind | важность | когда |
|---|---|---|
| `warden.started` | info | старт (с `dry_run` и `dry_run_source`: `config`, `cli` или `override`) |
| `warden.reloaded`, `warden.reload_failed` | info / warning | `SIGHUP` / `systemctl reload`; `notice` с `restart_required`, когда изменённая настройка читается только при старте (`daemon.state_dir`, `daemon.mlock`, `metrics.listen`, …) |
| `warden.dry_run` | notice | изменился действующий режим dry-run: `enabled`, `source` (`override` — `wardenctl dry-run on/off`, сохраняется между reload'ами и рестартами; `config` — reload, `wardenctl dry-run reset`, или override снят, потому что `dry_run` изменён в конфигурации; `cli` — `--dry-run`) и `reason`. Также при старте, если действует сохранённый override |
| `warden.quarantine_restored` | notice | файл из карантина восстановлен |
| `warden.tuning_reverted` | notice | отменены изменения sysctl, сделанные Warden |
| `warden.manual_snapshot` | notice | `wardenctl snapshot` |
