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

`ACK_WARDEN_LAB_SOURCE_TESTS=YES` — явное подтверждение запуска. Скрипт ставит зависимости для сборки (не пакет Warden), получает исходники и запускает workspace-тесты от `root` с одним тестовым потоком (`cargo test --workspace --locked -- --test-threads=1`). Установленный пакет не заменяется.

### Откуда берутся исходники

| Как запустить | Исходники | Что попадает в журнал |
| --- | --- | --- |
| без параметров | `main` из `https://github.com/commeta/warden`, checkout в `/opt/warden-lab/source/warden` | `Source commit` |
| `WARDEN_SOURCE_REF=v0.14.3` | указанная ветка, тег или commit | `Source commit` |
| `--source DIR` или `WARDEN_SOURCE_DIR=DIR` | каталог на стенде (ручное обновление: распакованный архив, рабочая копия) | `Source tree SHA-256`, `Source version`, commit, если в каталоге есть `.git` |

Ручное обновление — без доступа к GitHub и без push: скопируйте дерево исходников на стенд и укажите каталог.

```bash
scp warden-0.14.3.tar.gz warden@lab:~
ssh warden@lab 'tar -xzf warden-0.14.3.tar.gz'
cd ~/warden-lab-kit
sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES ./guest/70-warden-lab-source-tests.sh --source ~/warden-0.14.3
```

Каталог должен быть деревом Warden: `Cargo.toml` workspace, `Cargo.lock` и `crates/wardend`. Он копируется в `/opt/warden-lab/source/local` (владелец `root`, без `target/`, `.git/`, `fuzz/target/` и ссылок, ведущих за пределы дерева), и тесты идут в копии: сборка от `root` ничего не пишет в ваш каталог, а изменения в нём во время сборки не влияют на прогон. `Source tree SHA-256` — хеш всех файлов копии: по нему видно, какое именно дерево проверено.

### Где идёт сборка

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `WARDEN_LAB_BUILD_ROOT` | `/var/tmp/warden-lab-build` | кэш Cargo (`cargo-home/`), сборка (`target/`) и временные файлы тестов (`tmp/`, через `TMPDIR`) |
| `WARDEN_LAB_MIN_FREE_GIB` | `6` | меньше свободного места — скрипт не начинает сборку |
| `WARDEN_LAB_KEEP_TARGET` | `NO` | `YES` — оставить `target/` после прогона |

Отладочная сборка всего workspace занимает несколько ГиБ. На стенде 0.14.2 она лежала на корневой ФС, и `disk.space` предупреждал о 85 % заполнения `/` каждые полчаса. Теперь сборка идёт с отладочной информацией только по строкам (`line-tables-only`) и без инкрементального кэша, а `target/` и временные файлы удаляются после прогона, как бы он ни закончился. Если есть отдельный том, укажите его: `WARDEN_LAB_BUILD_ROOT=/srv/warden-build`. Каталог `/var/tmp/warden-lab-source-target` прежних ревизий удаляется.

Если установленный `wardend` работает, скрипт предупреждает: тесты запускают процессы, которые он может заметить (исполнение из `/tmp`, тестовые SUID-файлы, второй демон), и эти события попадут в его журнал. Остановите его на время прогона (`sudo systemctl stop wardend`), если журнал стенда должен остаться чистым.

### Результаты

```bash
sudo ls -lt /var/log/warden-lab/source-tests/
sudo grep -E 'test result:|Source (commit|tree SHA-256|version):|Test status:|Debian package still installed:|Daemon service state|FAILED|Finished' \
  /var/log/warden-lab/source-tests/*.log | tail -n 80
```

Успех — строки `test result: ok` без упавших тестов и итог скрипта `Test status: passed`. Запишите `Source commit` или `Source tree SHA-256`: результаты относятся именно к этому дереву.

## 3. Пример прогона: 0.14.2

- **Дата:** 28 октября 2026 года, журнал [`20261028T031044Z.log`](20261028T031044Z.log).
- **Исходники:** `main`, commit `2852c467c0eb8fa305003d73ee0e20815e5c596b` (`Update ci.yml`), версия 0.14.2.
- **Rust:** `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- **Установленный пакет:** `0.14.1-1`; `wardend` был остановлен до и после прогона.

| Набор | Тестов | Время |
| --- | ---: | ---: |
| `warden-core` и `reference_config` | 68 | 1,5 с |
| `warden-detect`: модульные, fingerprints, review, suspend, systemd D-Bus | 171 | 55 с |
| `warden-fuzz` | 4 | 3,2 с |
| `warden-respond`: модульные, review 0.13 и 0.14, suspend | 48 | 12,3 с |
| `warden-sys` | 94 | 783 с |
| `wardenctl` | 5 | 0,0 с |
| `wardend` и end-to-end | 34 | 31 с |
| **Всего** | **424** | ~15 мин |

Все 424 теста пройдены. 13 из 15 минут занял один `warden-sys`: тестовая фикстура `du` делала `fsync` на каждый из 3 000–5 000 файлов, а диск стенда был под нагрузкой (T1 ревью 0.14.2). В 0.14.3 фикстура пишет без `fsync` и строится на tmpfs (`/dev/shm`), если там есть место: на VM ревью рядом с двумя писателями с `fsync` набор `warden-sys` проходит за 6 с вместо 160 с.

Во время end-to-end сценариев в журнале встречаются сообщения `ERROR` и `WARN`, включая отказы тестового health endpoint, имитацию вредоносного PHP-файла и помещение файла в карантин. Это диагностика выполняемых сценариев, а не ошибки тестового раннера: соответствующие тесты завершились `ok`.

## 4. Ограничения и диагностика

- Результат относится к исходникам, версии Rust и условиям лабораторной машины из журнала. После обновления исходников повторите тесты и сохраните новый commit или хеш дерева.
- Если Rust не найден, проверьте `whoami`, `PATH`, `command -v cargo`, `command -v rustc` и `rustup show home`. Не устанавливайте Cargo через `sudo` для обхода проблемы с пользовательским окружением.
- Если тест завершился ошибкой, изучите полный журнал и первый тест с `FAILED` или `panicked`. Не удаляйте проверки и не ослабляйте защитный код только для того, чтобы тест стал зелёным.
- Успешный source-test не означает, что установленный Debian-пакет собран из того же дерева: это разные артефакты. Пакет из тех же исходников собирает `./scripts/build-deb.sh`, ставит его `guest/20-install-warden.sh` с `WARDEN_DEB_FILE` (README комплекта, раздел 4).
