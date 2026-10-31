# Установка Warden Lab Kit 2.0.5 на чистый Ubuntu Server 24.04 LTS

Документ относится к архиву `warden-lab-kit-2.0.5-lan-support.tar.gz` и пакету
Warden `0.14.3` для `amd64`. Upstream помечает `0.14.3` как pre-release; Kit
закрепляет его по версии и SHA-256, но для production следует отдельно согласовать
использование предварительного релиза. Warden по умолчанию работает в
observe-only / dry-run. Это лабораторный стенд с намеренно тестовыми целями —
не разворачивайте его на production-сервере.

## 1. Требования и сеть VirtualBox

Рекомендуется Ubuntu Server 24.04 LTS `amd64`, root/sudo, доступ по HTTPS к
GitHub Releases и доступ к APT-репозиториям Ubuntu. Для VirtualBox с NAT +
Host-Only обычно есть два интерфейса: NAT нужен для загрузок, Host-Only — для
доступа с хостовой машины. Узнать названия интерфейсов:

```bash
ip -br addr
ip -4 route
```

Например, `enp0s3` может быть NAT (`10.0.2.15/24`), а `enp0s8` — Host-Only
(`192.168.56.110/24`). Не копируйте эти значения вслепую: используйте вывод
своей машины.

## 2. Распаковать Kit

Загрузите архив на сервер и выполните:

```bash
tar -xzf warden-lab-kit-2.0.5-lan-support.tar.gz
cd warden-lab-kit-2.0
```

Если каталог проекта называется иначе, перейдите в фактический каталог,
содержащий `labctl` и `install.sh`.

## 3. Автоматическая LAN-установка

Узнайте IP хостовой машины на Host-Only-сети. Например, если хост имеет
`192.168.56.1`, выполните:

```bash
sudo ./install.sh --profile lan --iface enp0s8 --trusted 192.168.56.1/32
```

Замените `enp0s8` и `192.168.56.1/32` своими значениями. Можно передать несколько
доверенных CIDR через запятую, например `--trusted 192.168.56.1/32,192.168.56.2/32`.
Не передавайте `0.0.0.0/0` или `::/0`.

Установщик:

1. Проверит Ubuntu 24.04 и архитектуру `amd64`.
2. Сохранит существующий `lab.toml` в файл резервной копии, если он существует.
3. Установит bootstrap-пакеты для Python, TLS и загрузки релизов.
4. Сгенерирует `lab.toml` из LAN-шаблона с правильными CIDR.
5. Запустит `labctl doctor`, `plan`, `apply` и `verify`.
6. `labctl apply` установит остальные системные зависимости через APT.
7. Повторно отрендерит план после установки пакетов (например, теперь будет
   обнаружен `/etc/nginx/unicode.mapping`).
8. Загрузит Warden 0.14.3 по HTTPS, проверит SHA-256, установит пакет, проверит
   конфигурацию и включит `wardend.service`.

Для установки loopback-профиля без доступа из LAN используйте:

```bash
sudo ./install.sh --profile ci
```

## 4. Проверка служб

```bash
sudo ./labctl verify
sudo nginx -t
sudo systemctl --no-pager --full status nginx php8.3-fpm mariadb
sudo systemctl --no-pager --full status warden-lab-nftables wardend
sudo systemctl is-active nginx php8.3-fpm mariadb warden-lab-nftables wardend
sudo wardend --version
sudo wardenctl doctor
sudo wardenctl status
```

Успешная проверка `labctl verify` должна завершаться `OK all checks passed`.
Если `wardend` не запускается, изучите журнал:

```bash
sudo journalctl -u wardend.service -n 100 --no-pager
sudo wardend --check-config --config /etc/warden/warden.toml
```

## 5. Открыть портал с хостовой машины

На хостовом компьютере добавьте в `hosts` строку с реальным IP Ubuntu Server на
Host-Only-интерфейсе. Для шаблонных сайтов нужны имена портала и виртуальных
хостов WordPress/OpenCart:

```text
192.168.56.110 lab.local wordpress.lab.local opencart.lab.local
```

В Windows файл обычно находится по пути
`C:\Windows\System32\drivers\etc\hosts`. Замените IP на адрес сервера, затем
откройте `http://lab.local/` (порт 80, не 8080).

Правила nftables на сервере ограничивают TCP 80/443 источниками `trusted` на
заданном интерфейсе. Порты микросервисов 3100–3199 не публикуются для внешних
подключений. Для доступа нескольких хостов добавьте соответствующие IP/CIDR в
`trusted` и примените профиль повторно.

## 6. Проверки HTTP и WAF

На сервере:

```bash
curl -i -H 'Host: lab.local' http://127.0.0.1/
curl -i -H 'Host: lab.local' http://127.0.0.1/svc/node/health
curl -i -H 'Host: lab.local' http://127.0.0.1/svc/python-asgi/health
sudo nft list table inet lab_filter
sudo ./labctl test -m 'smoke or waf'
```

Для тестов `labctl test` установщик автоматически устанавливает `python3-pytest`
и `python3-pytest-timeout`.

## 7. Warden: безопасный первый запуск

В профиле используется:

```toml
[warden]
source = "release"
version = "0.14.3"
sha256 = "acc3e47112307cacdf4e025570f99e0afcc4131cf9e5395b554daaf68bc5470c"
enforce = false
```

Это намеренная настройка: Warden устанавливается и запускается, но действия
реагирования остаются в dry-run. Наблюдайте за событиями и ложными срабатываниями:

```bash
sudo wardenctl events -n 50
sudo journalctl -u wardend.service -f
```

Не включайте `enforce = true` до проверки allowlist, файловых путей, логов и
ложных срабатываний. При enforcement Warden может применять защитные действия,
в том числе блокировать адреса и изолировать файлы.

## 8. Повторный запуск и диагностика

После изменения конфигурации:

```bash
sudo ./labctl plan
sudo ./labctl apply
sudo ./labctl verify
```

Если конфигурация сети выдаёт `host bits set`, поле `net.v4_cidr` должно
содержать адрес сети, а не адрес интерфейса. Для встроенной сети лаборатории
используйте `10.77.0.0/24`; адрес внешнего интерфейса задаётся отдельно через
`net.external_iface`, а разрешённые клиенты — в `net.trusted`.

Если загрузка Warden не удалась, проверьте HTTPS/DNS и наличие закреплённого
актива релиза. Установщик не отключает проверку SHA-256 и не устанавливает
пакет с неизвестной контрольной суммой.


## 9. Полный набор интеграционных тестов

```bash
sudo ./labctl test
```

Команда запускает весь набор `tests/lab` без ограничения маркеров и выводит
сводку pytest. Чтобы выполнить только unit-тесты Kit (обычно на машине
разработчика), используйте `python3 -m pytest -q tests/unit`.
В LAN/loopback-профиле IPv6 namespace-тест может быть пропущен; тесты реального
Enforcement требуют отдельной disposable VM и явного флага `--enforce`.

В 2.0.5 для Warden генерируется отдельный точный `[[waf.log]]` источник на
каждый vhost. Каждый `[[fim.site]]` получает явный список `include`, в котором
есть прямые и вложенные PHP-family файлы в `uploads/`. Важно: поле `files` в
пользовательской сигнатуре Warden 0.14.3 фильтрует по basename, поэтому
`*.php` покрывает и `uploads/shell.php`; `**/*.php` в этом поле не требуется.

В 2.0.5 добавлен `warden-lab-fim-bridge.service`: он наблюдает `uploads/`
через inotify и при записи PHP/другого исполняемого типа запускает штатный
`wardenctl fim scan <site>`. Это запасной путь для файловых записей, которые
могут быть не видны mount-scoped realtime-сенсору в отдельном mount view systemd.
События объединяются; полное сканирование каждого сайта ограничено одним разом
в три секунды. Мост сохраняет sandbox сервисов и не отключает
`PrivateTmp`/`ProtectSystem`. Проверка службы:

```bash
sudo systemctl status warden-lab-fim-bridge.service --no-pager
sudo journalctl -u warden-lab-fim-bridge.service -n 50 --no-pager
sudo wardenctl fim status
sudo wardenctl fim scan svc-php-fpm
sudo wardenctl events -n 30
```

Мост наблюдает только Kit-managed `uploads/`; остальные изменения продолжают
обрабатываться штатным realtime FIM и периодическим сканированием Warden.

Nginx/ModSecurity продолжает писать аудит-логи от `www-data`, поэтому предупреждение
`wardenctl doctor` о владельце файла может сохраниться. При этом Kit задаёт
`waf.trust_writable_logs = false`: Warden продолжает читать и отображать события,
но не должен считать подделываемую веб-пользователем запись достаточным основанием
для автоматической блокировки IP. Проверьте итоговый drop-in и FIM:

```bash
sudo grep -nE '^path =|^site =|^name = "svc-|^include =|trust_writable_logs' \
  /etc/warden/conf.d/60-warden-lab.toml
sudo wardenctl doctor
sudo wardenctl status
sudo ./labctl test -m fim
```

Тест загрузки сначала проверяет, что HTTP 200 действительно создал файл с точным
маркером, и только затем ждёт событие `security.webshell`. Если событие не пришло,
тест выводит состояние FIM и моста, его последние логи и результат контрольного
ручного сканирования; тест при этом остаётся неуспешным, чтобы не скрывать пропуск
realtime-доставки. Файл остаётся на диске для диагностики. Выполните:

```bash
sudo find /var/www/warden-lab/services -path '*/uploads/shell-*.php' -type f -ls
sudo wardenctl fim scan svc-php-fpm
sudo wardenctl events -n 50
```

После диагностики удалите показанный `shell-<tag>.php` точным путём через `sudo rm -f`.
