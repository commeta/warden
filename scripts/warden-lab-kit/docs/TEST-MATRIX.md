# Матрица тестирования и критерии приёмки

Все сетевые сценарии выполняются локально на Ubuntu Server и ограничены `127.0.0.1`. Зарезервированный источник `127.0.0.2` применяется только в активном тесте блокировки Warden.

| Область | Триггер | Ожидаемое свидетельство | Проверка |
|---|---|---|---|
| Повторная установка Apache/Nginx | Повторный запуск установщика при работающем Nginx или упавшем Apache | Apache проходит configtest и слушает `127.0.0.1:8080` до запуска Nginx | `sudo ./guest/10-install-stack.sh`; `sudo apachectl configtest`; `ss -lntp` |
| CRS без дублей | Повторный запуск после старой конфигурации | Ровно один `owasp-crs.load`, нет `warden-lab-crs.conf`, нет ошибки duplicate rule ID | `sudo ./guest/30-validate.sh` |
| Health endpoint | `GET /health.php` | HTTP 200 | `./guest/40-waf-smoke.sh` |
| HTTPS | Запрос HTTPS health endpoint | HTTP 200 с тестовым self-signed сертификатом | `curl -k https://127.0.0.1/health.php` |
| XSS | `<script>` в `xss.php?q=` | CRS denial (обычно 403) и запись ModSecurity audit | `./guest/40-waf-smoke.sh`; audit log |
| SQL injection | Boolean condition в `sqli.php?id=` | CRS denial и audit transaction; DB-пользователь остаётся SELECT-only | `./guest/40-waf-smoke.sh` |
| Path traversal | `../` в `traversal.php?file=` | CRS denial и audit transaction | `./guest/40-waf-smoke.sh` |
| Warden WAF correlation | Пять разных denied-запросов от `127.0.0.1` при dry-run | `waf.hit` / `security.waf_attack` с отметкой allowlisted; адрес не блокируется | `wardenctl events -n 100`; `/var/log/warden/events.jsonl` |
| Warden firewall support | Проверить `nft` и диагностику Warden | `nft` установлен; `wardenctl doctor` проверяет возможности | `nft --version`; `wardenctl doctor` |
| Активная блокировка Warden | После review и явного `dry_run=false` отправить пять блокируемых запросов от `127.0.0.2` | `127.0.0.2` перестаёт отвечать; `127.0.0.1` по-прежнему HTTP 200; есть событие/action и запись blocklist | `sudo env ACK_WARDEN_ENFORCEMENT=YES ./guest/60-waf-block-test.sh`; затем восстановить dry-run и unblock |
| FIM | Создать безвредный файл в `public/uploads` | Событие изменения/нового файла; Apache не выполняет скрипты из uploads | README, `wardenctl fim scan main` |
| Безопасный command fixture | Запрос к `command-sim.php` | Обработчик отражает входные данные, shell не запускается | Проверить код и access-log |
| Проверка службы | Остановить и восстановить Nginx в отдельном тестовом окне | systemd state event и health-check evidence; активное действие зависит от dry-run | `systemctl stop nginx`; затем `systemctl start nginx` |
| Ротация журнала | Запустить logrotate в debug-режиме | Нет синтаксических ошибок; audit entries продолжают появляться | `sudo logrotate -d /etc/logrotate.d/warden-lab-modsecurity` |
| Границы доступности | Проверить слушающие сокеты | Только loopback listeners для `80,443,8080,3306` | `sudo ss -lntp`; `sudo ./guest/30-validate.sh` |
| Разделение таблиц | Проверить базовые правила и правила Warden | `inet lab_filter` не трогает `inet warden`; helpers не используют global flush | `sudo nft list table inet lab_filter`; `sudo nft list table inet warden` |
| Длительный прогон | `./guest/50-longrun-smoke.sh 60 8` | CSV с timestamp, ожидаемым и фактическим HTTP-кодом; ненулевой exit при любой ошибке | Проверить `results/*.csv` |
| Статические тесты комплекта | Запустить test runner | Bash/PHP/config/env template checks pass | `./tests/check-kit.sh` |

Активный тест разрешает только специально выделенный loopback source `127.0.0.2` и требует явного подтверждения. Он не должен запускаться с `dry_run=true`; он временно активирует все уже настроенные действия Warden, а не только IP block. Сделайте резервную копию `/etc/warden/warden.toml` и сразу восстановите `dry_run=true` после проверки. Храните исходные события и журналы. Полное покрытие произвольных инцидентов гарантировать нельзя: результат зависит от CRS, конфигурации приложения, возможностей ядра, правил Warden и корпуса испытаний.
