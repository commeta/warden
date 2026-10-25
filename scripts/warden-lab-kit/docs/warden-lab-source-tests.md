# Проверка исходного кода Warden из Lab Kit

Документ описывает запуск полного набора Rust-тестов Warden в Ubuntu Server 24.04 с помощью скрипта Lab Kit `guest/70-warden-lab-source-tests.sh`. 

> **Внимание:** запускайте тесты только на выделенном лабораторном сервере. Они выполняются от `root` и включают сценарии с процессами и файловой системой. Не запускайте их на production-системе.

## 1. Установить Rust под пользователем `warden`

Rust и Cargo должны быть установлены через `rustup` **в домашний каталог пользователя `warden`**, а не в окружение `root`.

Установите системные зависимости:

```bash
sudo apt-get update
sudo apt-get install -y curl ca-certificates build-essential pkg-config git
```

Перейдите в login-shell пользователя `warden` для примера (или войдите в систему непосредственно под ним):

```bash
sudo -iu warden
```

Убедитесь, что вы работаете под нужным пользователем, затем запустите официальный установщик `rustup` **без `sudo`**:

```bash
whoami
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup toolchain install stable
rustup default stable
```

Официальные инструкции: [rustup.rs](https://rustup.rs/) и [книга Rust — установка](https://doc.rust-lang.org/book/ch01-01-installation.html).

Проверьте установку:

```bash
whoami
command -v rustup
command -v rustc
command -v cargo
rustc --version
cargo --version
rustup show home
```

`whoami` должен вывести `warden`; ожидаемые пути к `rustup`, `rustc` и `cargo` — `/home/warden/.cargo/bin/`, каталог rustup — `/home/warden/.rustup`. Используйте Rust **1.88 или новее**, предпочтительно актуальный stable toolchain. Если команды не находятся, выполните `source "$HOME/.cargo/env"` и повторите проверки.

Если вы перешли в shell командой `sudo -iu warden`, после установки выйдите из него:

```bash
exit
```

## 2. Запустить полный набор тестов

Из каталога Lab Kit, где доступен подкаталог `guest/`, выполните:

```bash
sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES ./guest/70-warden-lab-source-tests.sh
```

`ACK_WARDEN_LAB_SOURCE_TESTS=YES` — явное подтверждение запуска. Скрипт подготавливает зависимости для сборки, обновляет исходный checkout и запускает workspace-тесты от `root` с одним тестовым потоком. Журнал сохраняется в `/var/log/warden-lab/source-tests/`; сборочные артефакты отделены от установленного пакета. В описанном успешном прогоне каталог сборки — `/var/tmp/warden-lab-source-target`.

Посмотреть журналы и найти последние результаты:

```bash
sudo ls -lt /var/log/warden-lab/source-tests/
sudo grep -E 'test result:|Source commit:|Debian package still installed:|Daemon service state after tests:|TESTS FAILED|Finished' \
  /var/log/warden-lab/source-tests/*.log | tail -n 80
```

Успех подтверждается итогом Cargo без упавших тестов, строками `test result: ok` и итоговым сообщением скрипта `Finished`. Запишите SHA исходного commit из журнала: результаты относятся именно к нему.

## 3. Пример успешного прогона

- **Дата:** 25 октября 2026 года.
- **Исходный commit:** `7b9e49ada42d31264e092785a4609e037f44948d` (`Add files via upload`).
- **Rust:** `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- **Журнал:** `/var/log/warden-lab/source-tests/20261025T211155Z.log`. [20261025T211155Z.log](20261025T211155Z.log)
 

| Набор | Пройдено тестов |
| --- | ---: |
| `warden-core` и `reference_config` | 65 |
| `warden-detect`, fingerprints, review, suspend, systemd D-Bus | 141 |
| `warden-fuzz` | 3 |
| `warden-respond`, review и suspend | 45 |
| `warden-sys` | 91 |
| `wardenctl` | 5 |
| `wardend` и end-to-end | 33 |
| **Всего** | **383** |

**Итог: 383 теста пройдены, 0 ошибок.** В `warden-respond` успешно прошёл `quarantine::tests::put_survives_a_file_symlink_swap_race` — тест гонки при подмене файла символической ссылкой. End-to-end тесты также завершились успешно. Самым длительным был пакет `warden-sys`: 91 тест за 778,15 секунды; в том числе прошёл `selfstat::tests::a_peak_is_returned_even_under_mlockall`.

Во время end-to-end сценариев в журнале встречаются сообщения `ERROR` и `WARN`, включая отказы тестового health endpoint, имитацию вредоносного PHP-файла и помещение файла в карантин. В данном прогоне это диагностические сообщения выполняемых сценариев, а не ошибки тестового раннера: соответствующие тесты завершились `ok`.

Скрипт сообщил, что установленный Debian-пакет остался версии `0.14.1-1`, а служба Warden была `active` до и после тестов. Таким образом, прогон проверил исходный код указанного commit, не обновляя установленный пакет.

## 4. Ограничения и диагностика

- Результат относится к commit, версии Rust и условиям лабораторной машины из журнала. После обновления исходников повторите тесты и сохраните новый SHA.
- Полный прогон может занимать значительное время: тесты в `warden-sys` в приведённом примере заняли около 13 минут.
- Если Rust не найден, проверьте `whoami`, `PATH`, `command -v cargo`, `command -v rustc` и `rustup show home`. Не устанавливайте Cargo через `sudo` для обхода проблемы с пользовательским окружением.
- Если тест завершился ошибкой, изучите полный журнал и первый тест с `FAILED` или `panicked`. Не удаляйте проверки и не ослабляйте защитный код только для того, чтобы тест стал зелёным.
- Успешный source-test не означает, что установленный Debian-пакет собран из того же commit: это разные артефакты, и версию пакета следует проверять отдельно.
