# Фаззинг

У каждого парсера, который читает входные данные, не контролируемые Warden, здесь есть цель:

| цель | входные данные |
|---|---|
| `access_log` | строки access-log веб-сервера (`fim.site.access_log`); также проверяет, что время — это поле в скобках перед запросом (B15) |
| `modsecurity` | ModSecurity v2 (error log Apache), v3 (error log nginx) и JSON-записи аудита |
| `dbus` | сообщения D-Bus с системной шины и распаковщик тела с произвольными сигнатурами |
| `proc_connector` | датаграммы netlink proc connector |
| `fanotify` | буферы чтения fanotify, обычные и с записями FID/DFID_NAME |
| `procfs` | текст `/proc` и `/sys` (`stat`, `status`, `cgroup`, `limits`, `mountinfo`, `net/*`, PSI, `meminfo`, `vmstat`, `modules`), `/etc/passwd`, записи `/dev/kmsg` |
| `auth_log` | строки `auth.log` / journald в анализатор с состоянием |
| `redact` | редактор секретов, через который проходит всё вышеперечисленное на пути к уведомлению |

Тела живут в [`crates/warden-fuzz`](../crates/warden-fuzz/src/lib.rs),
так что `cargo test -p warden-fuzz` прогоняет их на стабильном тулчейне по seed-корпусу и
несколько тысяч детерминированных мутаций (без паники, без входа, обрабатываемого дольше
секунды). С libFuzzer (nightly):

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run dbus -- -max_total_time=300 -max_len=8192 -rss_limit_mb=1024 -timeout=10
```

`corpus/<target>/` хранит seed-файлы (пересоздать через
`WARDEN_FUZZ_CORPUS=fuzz/corpus cargo test -p warden-fuzz write_corpus`) и
входы `regress-*` для найденных здесь багов, сохранённые как регрессионные seed'ы:

* `access_log`: поле времени вроде `2026:9999999999999:…` переполняло
  арифметику времени (`parse_clf_time` теперь отвергает поля вне диапазона);
* `dbus`: сигнатура `a()` — массив пустых структур — читала ноль байт
  на элемент и росла безгранично, 23 байта исчерпывали память (пустые
  структуры отвергаются, элементы массива обязаны потреблять входные данные);
* `procfs`: экранирование в mountinfo `\545` переполняло байт;
* `procfs` (CI, 27.10.2026): `VmRSS: 59999999999991024 kB` переполнял
  `n * 1024` в `parse_kb_value` (паника в debug, тихий перенос в release) —
  теперь `checked_mul`, значение отвергается.

`cargo test -p warden-fuzz` прогоняет все `regress-*` на стабильном
тулчейне, так что исправление не может незаметно откатиться.

CI прогоняет каждую цель отдельным заданием (матрица `fuzz`): по минуте на
каждый push и pull request и по 10 минут каждую ночь, на корпусе, выращенном
прошлыми прогонами (кэш). Nightly-тулчейн закреплён (`FUZZ_TOOLCHAIN` в
`ci.yml`) — обновлять осознанно; падения выгружаются артефактом
`fuzz-crash-<цель>`.
Без nightly-тулчейна цели всё равно можно собирать с coverage-guided-фаззингом на
стабильном тулчейне — так они и были найдены:

```bash
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow-checks" \
  cargo build --release --bins --target x86_64-unknown-linux-gnu --target-dir target/cov
target/cov/x86_64-unknown-linux-gnu/release/dbus corpus/dbus -max_total_time=120
```
