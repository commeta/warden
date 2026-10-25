# Warden Lab Kit — автономный стенд Ubuntu Server 24.04

Локальный стенд для проверки ModSecurity 2.9, OWASP CRS и Warden на одной системе Ubuntu Server 24.04 LTS. Все тестовые запросы идут через loopback: `Nginx 127.0.0.1:80/443 → Apache prefork + PHP 8.3 mod_php 127.0.0.1:8080 → MySQL 127.0.0.1:3306`. Тестовое приложение с демонстрационными XSS/SQLi/path traversal endpoint-ами предназначено только для лабораторных проверок.

> Не используйте комплект на production-сервере или с реальными данными. Для установки пакетов и скачивания Warden нужен обычный доступ к репозиториям. После установки smoke-тесты и тест блокировки Warden выполняются локально.

## 1. Подготовить конфигурацию

Распакуйте архив в `~/warden-lab-kit` на Ubuntu Server 24.04.

```bash
cd ~/warden-lab-kit
cp -n lab.env.example lab.env
chmod 600 lab.env
nano lab.env
./guest/01-prepare.sh
```

По умолчанию `LAB_IP=127.0.0.1` используется для обычных проверок, а `ATTACKER_IP=127.0.0.2` — исключительно как отдельный локальный источник в явном тесте блокировки Warden. Не меняйте их без понимания механизма allowlist. `lab.env` не выполняется как shell-код; парсер отвергает повторяющиеся ключи и небезопасные строки. Сетевые интерфейсы и адреса не перенастраиваются.

## 2. Установить веб-стек и nftables

```bash
sudo ./guest/10-install-stack.sh
sudo ./guest/30-validate.sh
```

Устанавливаются и настраиваются:

- Nginx: `127.0.0.1:80/443`, включая self-signed TLS для тестов.
- Apache `mpm_prefork + mod_php 8.3 + security2`: `127.0.0.1:8080`.
- MySQL `127.0.0.1:3306`; учётная запись приложения имеет только `SELECT`.
- ModSecurity v2 с serial audit log `/var/log/apache2/modsec_audit.log` и OWASP CRS.
- Нативный nftables: таблица `inet lab_filter` отбрасывает входящий трафик на порты `80,443,8080,3306` с любых интерфейсов, кроме `lo`. Таблица `inet warden` остаётся исключительно под управлением Warden. Скрипты меняют только принадлежащую им таблицу/цепочку и не используют глобальный `flush ruleset`.
- DB-пароль: `/etc/warden-lab/db-password` (`root:root`, `0600`); PHP-конфигурация вне webroot `/etc/warden-lab/db.php` (`root:www-data`, `0640`); каталог `/etc/warden-lab` — `root:www-data`, `0710`.
- Журнал ModSecurity ротируется, размер journald ограничивается для длительных прогонов.

Установщик специально не включает штатный `nftables.service`: системный `/etc/nftables.conf` может загрузить широкий ruleset. Вместо него применяется собственная `warden-lab-nftables.service`, которая поднимает только `inet lab_filter`. Если штатная служба уже активна/включена, скрипт останавливается для ручной проверки.

**Уязвимость пакета ModSecurity:** в Ubuntu 24.04 версия `libapache2-mod-security2` может отличаться по доступным исправлениям; проверьте `apt-cache policy libapache2-mod-security2`. Ubuntu Security Notice USN-7567-1 перечислял исправления для Noble через Ubuntu Pro / ESM Apps. Это лабораторный стенд, не production. [Package](https://packages.ubuntu.com/noble/libapache2-mod-security2) · [CRS package](https://packages.ubuntu.com/noble/modsecurity-crs) · [USN-7567-1](https://ubuntu.com/security/notices/USN-7567-1).

Ручные проверки:

```bash
sudo apachectl configtest
sudo nginx -t
sudo apachectl -M | grep -E 'security2|php|mpm_prefork|remoteip'
sudo nft list table inet lab_filter
sudo ss -lntp
```

Ожидаемые listeners: `127.0.0.1:80`, `127.0.0.1:443`, `127.0.0.1:8080`, `127.0.0.1:3306`. Если любой сервис слушает `0.0.0.0`, `::` или иной адрес вне loopback, исправьте это перед тестированием.

## 3. Запустить локальные тесты ModSecurity

```bash
./guest/40-waf-smoke.sh
```

Проверяются health endpoint, HTTPS, XSS, SQLi и path traversal. Smoke-test делает пять различных заблокированных запросов, достаточных для достижения `waf.block_after=5` в Warden. Запросы идут с allowlisted адреса `127.0.0.1`, поэтому штатный smoke-test не должен блокировать источник. При ошибке проверьте `sudo ./guest/30-validate.sh`, `/var/log/apache2/error.log` и `/var/log/apache2/modsec_audit.log`.

Длительный тест с CSV-результатами (по умолчанию раз в 60 секунд в течение 8 часов):

```bash
./guest/50-longrun-smoke.sh 60 8
```

Параметры: интервал в секундах (минимум 10) и длительность в часах (1–168). Выходной файл создаётся в `results/`. Скрипт возвращает ненулевой код, если хотя бы одна проверка не прошла. Для досрочной остановки используйте Ctrl-C.

## 4. Установить Warden

Изучите исходники и релиз, подтвердите риск prerelease.

```bash
sudo env ACK_WARDEN_PRERELEASE_RISK=YES ./guest/20-install-warden.sh
sudo wardenctl doctor
sudo systemctl enable --now wardend
sudo wardenctl status
sudo wardenctl events -f
```

Drop-in `/etc/warden/conf.d/60-warden-lab.toml` связывает Warden с FIM каталога сайта, Nginx access-log, ModSecurity audit log и health-check. `127.0.0.1` разрешён в allowlists для штатных проверок. `127.0.0.2` намеренно не входит в allowlist и зарезервирован только для отдельного активного теста. Основной `/etc/warden/warden.toml` остаётся в `dry_run = true`.

**Не выключайте `dry_run` в начале тестов.** Сначала разберите ложные срабатывания и проверьте процедуру восстановления.

## 5. FIM и активная проверка блокировки Warden

Безопасный smoke-test выше работает в dry-run. Для проверки настоящей IP-блокировки нужно явно включить enforcement на время эксперимента. Важно: `dry_run=false` разрешает все настроенные действия демона, а не только блокировку IP; выполняйте тест только на отдельной лабораторной системе, не используемой для других задач, после резервной копии конфигурации.

Сохраните и измените конфигурацию вручную:

```bash
sudo cp -a /etc/warden/warden.toml /etc/warden/warden.toml.pre-enforce
sudo sed -i -E 's/^[[:space:]]*dry_run[[:space:]]*=.*/dry_run = false/' /etc/warden/warden.toml
sudo wardend --check-config --config /etc/warden/warden.toml
sudo systemctl reload wardend
sudo wardenctl status
```

Убедитесь, что Warden действительно работает с `dry_run=false`, затем запустите:

```bash
sudo env ACK_WARDEN_ENFORCEMENT=YES ./guest/60-waf-block-test.sh
```

Тест использует `curl --interface 127.0.0.2` для обращения к локальному Nginx на `127.0.0.1`. `RemoteIPInternalProxy 127.0.0.1` позволяет Apache получить клиентский адрес из заголовка доверенного локального reverse proxy. ModSecurity записывает адрес в audit log, после пяти заблокированных запросов Warden должен заблокировать source IP в `inet warden`. Тест требует сразу нескольких свидетельств: source `127.0.0.2` перестаёт получать HTTP-ответ, контрольный source `127.0.0.1` продолжает получать HTTP 200, в событиях есть `security.waf_attack` / `action.block_ip`, а IP присутствует в nftables blocklist.

**Сразу восстановите dry-run после теста:**

```bash
sudo cp -a /etc/warden/warden.toml.pre-enforce /etc/warden/warden.toml
sudo wardend --check-config --config /etc/warden/warden.toml
sudo systemctl reload wardend
sudo wardenctl unblock 127.0.0.2
sudo wardenctl status
```

Если активный тест оборвался, выполните восстановление вручную. Не оставляйте `dry_run=false` после проверки.

Проверка FIM с безопасным файлом в uploads:

```bash
sudo -u www-data sh -c 'printf "<?php // harmless FIM fixture ?>\n" > /var/www/warden-lab/public/uploads/fim-test.php'
sudo wardenctl fim scan main
sudo wardenctl events -n 30
sudo rm -f /var/www/warden-lab/public/uploads/fim-test.php
```

Apache запрещает выполнение скриптов в uploads, но каталог остаётся доступным для FIM-проверок.

## 6. Дополнительные проверки и журналы

```bash
./tests/check-kit.sh
sudo ./guest/30-validate.sh
sudo nft list table inet lab_filter
sudo nft list table inet warden  # может отсутствовать до первой активной блокировки
sudo logrotate -d /etc/logrotate.d/warden-lab-modsecurity
sudo journalctl -u nginx -u apache2 -u mysql --since today
sudo tail -F /var/log/nginx/access.log /var/log/nginx/error.log
sudo tail -F /var/log/apache2/access.log /var/log/apache2/error.log /var/log/apache2/modsec_audit.log
sudo journalctl -u wardend -f
sudo tail -F /var/log/warden/events.jsonl
```

`tests/check-kit.sh` проверяет Bash/PHP, шаблоны конфигураций, формат `lab.env`, Warden TOML, loopback-binding и соответствие локальных тестов текущим файлам. Он не заменяет проверки работающих служб.

## 7. Основные пути

- Nginx: `/etc/nginx/sites-available/warden-lab`
- Apache: `/etc/apache2/sites-available/warden-lab.conf`
- ModSecurity: `/etc/modsecurity/modsecurity.conf`
- ModSecurity audit: `/var/log/apache2/modsec_audit.log`
- Тестовый сайт: `/var/www/warden-lab/public`
- Каталог FIM-проверок: `/var/www/warden-lab/public/uploads`
- DB secret: `/etc/warden-lab/db-password`; PHP config: `/etc/warden-lab/db.php`
- Warden: `/etc/warden/warden.toml`, `/etc/warden/conf.d/60-warden-lab.toml`
- Результаты длительного прогона: `results/*.csv`

Полное покрытие всех возможных инцидентов гарантировать нельзя. Используйте `docs/TEST-MATRIX.md` для фиксации триггера, ожидаемого события, сырого журнала и критерия приёмки каждого сценария.
