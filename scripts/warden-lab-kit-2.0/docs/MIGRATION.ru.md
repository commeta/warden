# Переход с Lab Kit 1.x

1.x — девять императивных bash-скриптов, Apache + ModSecurity 2.9 на loopback,
атакующий `127.0.0.2`, один из шести режимов журнала, без изоляции. 2.0 —
декларативный `labctl` с манифестом, несколькими фронтами, namespace, IPv6 и
внешними тестами.

## Миграция конфигурации

Старый `lab.env` (5 ключей) превращается в `lab.toml`:

```bash
sudo ./labctl migrate --env /путь/к/lab.env --out lab.toml
```

Выходит профиль `apache-prefork` + ModSecurity 2.9 + serial-native на loopback —
эквивалент 1.x. Проверьте его и запустите `sudo ./labctl plan`. Чтобы получить
новое (настоящий дроп не на `lo`, IPv6, блокировки), смените `net.mode` на
`netns`, а для production — на `external` с `external_iface` и `trusted`.

## Соответствие

| 1.x | 2.0 |
|---|---|
| `guest/10-install-stack.sh` | роли `front`, `waf`, `crs`, `db`, `app_php` |
| `guest/20-install-warden.sh` | роль `warden` (`[warden] source = release\|deb\|source`) |
| `guest/30-validate.sh`, `40-waf-smoke.sh` | `labctl verify`, `labctl test -m smoke` |
| `guest/60-waf-block-test.sh` | `labctl test -m enforce` (с `LAB_ENFORCE=1`) |
| `guest/70-warden-lab-source-tests.sh` | `[warden] source = source` + `labctl apply` |
| `lib/lab-common.sh` (парсер `lab.env`) | `lab/profile.py` (TOML) + `labctl migrate` |
| `tests/check-kit.sh` | `tests/unit/` (pytest) + ruff + shellcheck в CI |

## Что сохранено из 1.x

Строгий разбор конфигурации без исполнения, секреты вне дерева проекта с
проверкой прав, собственная таблица nftables с маркером владения без
`flush ruleset`, явные подтверждения перед опасными шагами (`LAB_ENFORCE`),
SHA-256 пакета Warden перед установкой.

## Чего в 1.x не было

Манифест и удаление осиротевших файлов (L1), `target`/сборка вне корня (L2),
привязка проверок к своему прогону по `t=<uuid>` (L3), namespace и IPv6 (L4),
изоляция собственной нагрузки в slice (L5), установка из PR/исходников/локального
.deb (L6), несколько движков и все 6 режимов журнала (L7), версии только из
профиля (L8), безопасное включение/возврат enforce (L9), тесты вместо grep по
скриптам (L10), `soak`/`report` с метриками (L11), фиксация версий пакетов в
отчёте (L12).
