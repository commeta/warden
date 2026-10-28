# Матрица тестирования и критерии приёмки

Все сетевые сценарии выполняются локально на Ubuntu Server и ограничены `127.0.0.1`. Зарезервированный источник `127.0.0.2` применяется только в активном тесте блокировки Warden.

| Область | Триггер | Ожидаемое свидетельство | Проверка |
|---|---|---|---|
| Повторная установка Apache/Nginx | Повторный запуск установщика при работающем Nginx или упавшем Apache | Apache проходит configtest и слушает `127.0.0.1:8080` до запуска Nginx | `sudo ./guest/10-install-stack.sh`; `sudo apachectl configtest`; `ss -lntp` |
| CRS без дублей | Повторный запуск после старой конфигурации | Ровно один `owasp-crs.load`, нет `warden-lab-crs.conf`, нет ошибки duplicate rule ID | `sudo ./guest/30-validate.sh` |
| Health endpoint | `GET /health.php` | HTTP 200 | `./guest/40-waf-smoke.sh` |
| HTTPS | Запрос HTTPS health endpoint | HTTP 200 с тестовым self-signed сертификатом | `curl -k https://127.0.0.1/health.php` |
| XSS | `<script>` в `xss.php?q=` | CRS denial (обычно 403) и запись ModSecurity audit именно этого запроса (метка `wlt=` прогона в журнале аудита) | `./guest/40-waf-smoke.sh`; `sudo ./guest/30-validate.sh` |
| SQL injection | Boolean condition в `sqli.php?id=` | CRS denial и audit transaction; DB-пользователь остаётся SELECT-only | `./guest/40-waf-smoke.sh` |
| Path traversal | `../` в `traversal.php?file=` | CRS denial и audit transaction | `./guest/40-waf-smoke.sh` |
| Warden WAF correlation | Пять разных denied-запросов от `127.0.0.1` при dry-run | `waf.hit` / `security.waf_attack` с отметкой allowlisted; адрес не блокируется | `wardenctl events -n 100`; `/var/log/warden/events.jsonl` |
| Warden firewall support | Проверить `nft` и диагностику Warden | `nft` установлен; `wardenctl doctor` проверяет возможности | `nft --version`; `wardenctl doctor` |
| Активная блокировка Warden | После review и явного `dry_run=false` отправить пять блокируемых запросов от `127.0.0.2` | `127.0.0.2` перестаёт отвечать; `127.0.0.1` по-прежнему HTTP 200; после начала теста есть `security.waf_attack` и `action.block_ip` (`done`) именно для `127.0.0.2`; адрес — точным значением — в `inet warden blocklist4` | `sudo env ACK_WARDEN_ENFORCEMENT=YES ./guest/60-waf-block-test.sh`; затем восстановить dry-run и unblock |
| FIM | Создать безвредный файл в `public/uploads` | Событие изменения/нового файла; Apache не выполняет скрипты из uploads | README, `wardenctl fim scan main` |
| Безопасный command fixture | Запрос к `command-sim.php` | Обработчик отражает входные данные, shell не запускается | Проверить код и access-log |
| Проверка службы | Остановить и восстановить Nginx в отдельном тестовом окне | systemd state event и health-check evidence; активное действие зависит от dry-run | `systemctl stop nginx`; затем `systemctl start nginx` |
| Ротация журнала | Запустить logrotate в debug-режиме | Нет синтаксических ошибок и дублей: журнал аудита ротирует только `/etc/logrotate.d/apache2`; `logrotate.service` не в состоянии failed | `sudo logrotate -d /etc/logrotate.conf`; `systemctl is-failed logrotate.service` |
| Остаток прежних ревизий | Обновить Warden на стенде одним `20-install-warden.sh` | `/etc/logrotate.d/warden-lab-modsecurity` удалён, logrotate принимает конфигурацию | `sudo env ACK_WARDEN_PRERELEASE_RISK=YES ./guest/20-install-warden.sh` |
| Своя сборка Warden | Поставить `.deb`, собранный из исходников, а не релиз | Пакет с хешем из `WARDEN_DEB_FILE_SHA256` установлен, `wardend --check-config` проходит | README, раздел 4 |
| Границы доступности | Проверить слушающие сокеты | Только loopback listeners для `80,443,8080,3306` | `sudo ss -lntp`; `sudo ./guest/30-validate.sh` |
| Разделение таблиц | Проверить базовые правила и правила Warden | `inet lab_filter` не трогает `inet warden`; helpers не используют global flush | `sudo nft list table inet lab_filter`; `sudo nft list table inet warden` |
| Длительный прогон | `./guest/50-longrun-smoke.sh 60 8` | CSV с timestamp, ожидаемым и фактическим HTTP-кодом; ненулевой exit при любой ошибке | Проверить `results/*.csv` |
| Статические тесты комплекта | Запустить test runner | Bash/PHP/config/env template checks pass | `./tests/check-kit.sh` |
| Тесты исходников | Прогнать Rust-тесты из GitHub или из каталога на стенде | `test result: ok` во всех наборах, `Test status: passed`; в журнале commit или SHA-256 дерева; `target/` удалён, корневая ФС не заполнена | `sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES ./guest/70-warden-lab-source-tests.sh [--source DIR]` |
| IPv6 /64 (0.14.3) | Атакующий меняет адрес внутри одной /64 | Один `security.waf_attack` и один блок `…/64` в `blocklist6_64`; IPv4-соседи — по адресу. Стенд IPv6 не проверяет (только loopback IPv4) | модульные тесты; в исходниках Warden: `sudo python3 -I bench/stress.py --wardend target/profiling/wardend --only waf_v6_spread` (одноразовая VM) |

Активный тест разрешает только специально выделенный loopback source `127.0.0.2` и требует явного подтверждения. Он не должен запускаться с `dry_run=true`; он временно активирует все уже настроенные действия Warden, а не только IP block. Сделайте резервную копию `/etc/warden/warden.toml` и сразу восстановите `dry_run=true` после проверки. Храните исходные события и журналы. Полное покрытие произвольных инцидентов гарантировать нельзя: результат зависит от CRS, конфигурации приложения, возможностей ядра, правил Warden и корпуса испытаний.
