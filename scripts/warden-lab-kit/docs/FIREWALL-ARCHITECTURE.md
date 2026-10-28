# Архитектура nftables — локальный стенд

- `inet lab_filter` — базовая таблица, которую создаёт `warden-lab-nftables.service`. Цепочка `input` имеет `policy accept`, но отбрасывает TCP-подключения к `80,443,8080,3306`, если входящий интерфейс не `lo`. Это дополнительный барьер, а не замена общей политике firewall системы.
- Nginx, Apache и MySQL слушают только `127.0.0.1`; тестовые запросы выполняются локально.
- `inet warden` — таблица, которой управляет Warden для временной блокировки IP. Базовый helper её не очищает и не пересоздаёт. С 0.14.3 в ней три набора: `blocklist4` (адреса IPv4), `blocklist6` (отдельные адреса IPv6) и `blocklist6_64` (сети IPv6 /64, правило `ip6 saddr & ffff:ffff:ffff:ffff:: @blocklist6_64`). Все — обычные хеш-наборы с таймаутом; блоки добавляются пачками, одной транзакцией `nft -f -`.
- `127.0.0.1` разрешён в Warden allowlist для штатных проверок. `127.0.0.2` — отдельный loopback source для активного теста; его намеренно нет в allowlist.
- Обновления применяются через `nft --check -f` и затем `nft -f`; helper обновляет только `inet lab_filter input`. Глобальный `flush ruleset` не используется.
- Штатный `nftables.service` не включается: неизвестный `/etc/nftables.conf` может загрузить весь ruleset. Используется отдельный systemd unit.
- Если уже активно другое управление nftables или UFW, установщик остановится для ручной проверки; существующий firewall автоматически не отключается.

## Проверка

```bash
sudo systemctl status warden-lab-nftables.service
sudo nft list table inet lab_filter
sudo nft list table inet warden       # может отсутствовать до первого активного block action
sudo wardenctl doctor
sudo wardenctl events -n 100
```

Активный тест выполняется `sudo env ACK_WARDEN_ENFORCEMENT=YES ./guest/60-waf-block-test.sh` после ручного включения `dry_run=false`. После теста обязательно восстановите `dry_run=true` и выполните `sudo wardenctl unblock 127.0.0.2`.
