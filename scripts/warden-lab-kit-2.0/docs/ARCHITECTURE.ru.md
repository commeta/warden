# Lab Kit 2.0 — архитектура

## Профиль → роли → хост

`labctl` читает `lab.toml`, строит из него список ролей, каждая роль
**отрисовывает** набор файлов (путь, содержимое, владелец, режим, какой юнит
перезапустить) — и ничего не пишет сама. Пишет только движок манифеста
(`apply`): сверяет отрисованное с `/var/lib/warden-lab/state.json`, пишет
изменившееся, удаляет осиротевшее, валидирует конфиги и перезапускает только
затронутые юниты. Это закрывает класс ошибок L1 ревью: исправление из новой
версии kit всегда доходит до стенда, а файл, который роль перестала отдавать,
удаляется.

```
lab.toml ──▶ profile.load (+ матрица совместимости)
                  │
                  ▼
      roles: base · net · tls · db · crs · waf · front · app_php · svc · warden
                  │  каждая: packages / users / pre_apply / render / post_apply / verify
                  ▼
      manifest.apply ── сверка с state.json ── пишет/удаляет ── validate ── restart
```

## Роли (порядок применения)

| Роль | Отвечает за |
|---|---|
| `base` | каталоги kit, slice для своей нагрузки, секрет БД (root-only) |
| `net` | таблица `inet lab_filter`, namespace клиента и атакующего (netns/external) |
| `tls` | сертификат фронта (self-signed / files / ACME) |
| `db` | MariaDB / PostgreSQL / Redis (опционально), health-пробы |
| `crs` | OWASP CRS из пакета или закреплённого тега 4.x |
| `waf` | ModSecurity 2.9 или libmodsecurity 3, один из 6 режимов журнала |
| `front` | nginx / Apache / edge-прокси, vhost на сайт, прокси `/svc/<имя>/` |
| `app_php` | сайты-движки: пользователь, docroot, пул FPM, access-log на сайт |
| `svc` | микросервисы: пользователь, код, ужесточённый юнит systemd |
| `warden` | установка Warden и генерация drop-in из всего, что собрали роли |

## Матрица совместимости фронт × WAF

`labctl plan` отклоняет несовместимый профиль до установки.

| Фронт | ModSecurity 2.9 | libmodsecurity 3 | PHP | Что проверяет |
|---|---|---|---|---|
| `nginx` | — | да | FPM | журнал пишет воркер (N5), нет IncludeOptional |
| `apache-prefork` | да | — | mod_php | PHP в процессе сервера; аудит `root:adm 0640` |
| `apache-event` | да | — | FPM | `web_spawn` из пула FPM под своим пользователем |
| `haproxy` | — | через nginx+MS3 | FPM | X-Forwarded-For, два уровня прокси |
| `caddy` | — | через nginx+MS3 | FPM | X-Forwarded-For, TLS на edge |

Edge-фронты (HAProxy, Caddy) не несут своего WAF: они ставятся перед
внутренним уровнем nginx + ModSecurity 3 на `127.0.0.1:8080`, который по
`X-Forwarded-For` восстанавливает настоящий адрес клиента — от этого зависит,
какой адрес заблокирует Warden.

## 6 режимов журнала ModSecurity

Параметр `waf.mode`; `labctl apply --set waf.mode=…` переключает на одном стенде.

| Режим | Директивы ModSecurity | Что читает Warden |
|---|---|---|
| `serial-native` | `SecAuditLogType Serial`, нативный | `path=.../audit.log format=native` |
| `serial-json` | `+ SecAuditLogFormat JSON` | `format=json` |
| `per-site` | `SecAuditLog` на каждый vhost | `path=.../sites/*/audit.log site={1}` |
| `concurrent-index` | `Concurrent` + индекс | `format=concurrent storage_dir=…` |
| `concurrent-noindex` | `Concurrent`, Warden сканирует каталог | `path=<каталог> format=concurrent` |
| `error-log` | `SecAuditEngine Off` | `path=<error.log> format=error_log` |

CRS — пакетный 3.3.5 или закреплённый тег 4.x (`crs.ref` + `crs.sha256`;
`labctl crs-digest <тег>` печатает хеш). Логика заголовка события в Warden
зависит от номеров правил 949/959/980, поэтому CRS закрепляется.

## Манифест

`/var/lib/warden-lab/state.json` — каждый файл и каталог kit с ролью и SHA-256.
`apply`:

1. чужой файл по пути kit отодвигается в `/var/lib/warden-lab/displaced/`;
2. пишется только то, что изменилось по хешу/режиму/владельцу;
3. файлы из манифеста, которых больше нет в плане, удаляются (осиротевшие);
4. валидируются конфиги фронта/WAF и `wardend --check-config`;
5. перезапускаются только юниты, чьи файлы изменились.

`reset` снимает всё из манифеста, самые глубокие пути первыми.

## Сеть

| Режим | Клиент | Атакующий | Для чего |
|---|---|---|---|
| `loopback` | 127.0.0.1 | 127.0.0.2 | работает везде (CI без caps); блок на `lo` |
| `netns` | namespace `lab-cli` (в allowlist) | `lab-atk`, `IP_FREEBIND` на целые диапазоны | настоящий дроп не на `lo`, ротация IPv6 /64, флуд с тысяч адресов |
| `lan` | `net.trusted` | только заданные CIDR на выбранном NIC | доступ к веб-фронту из LAN; прочие внешние источники и backend-порты блокируются |
| `external` | реальные сети из `net.trusted` | извне | эталон production: фронт на NIC |

Таблица `inet lab_filter` — дополнительный барьер kit; это **не** таблица
Warden (`inet warden`), kit её не трогает и не делает `flush ruleset`. В
локальных режимах порты сервисов доступны только с `lo` и veth стенда; в
`external` фронт (80/443) открыт на NIC, порты микросервисов закрыты, новые
HTTP-соединения ограничены по скорости как грубый бэкстоп (настоящие блокировки
делает Warden в своей таблице, на более высоком приоритете).
