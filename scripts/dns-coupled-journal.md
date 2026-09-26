# Совместный журнал DNS-интерфейса и настроек resolved

На 2026-09-26: два реальных прогона **PASS** (повторный ~165 секунд), 17 controller SIGKILL, 6 отказов,
remaining owned links=0, final processes=1/zombies=0. Node acceptance —
**1315/1315 PASS**, без skips; targeted coupled/parser/evidence — 82/82 PASS.

Изолированный namespace-координатор: один контроллер и один process-lifetime
`flock` управляют созданием dummy-link, адресом/UP, настройками resolved и
отключением в обратном порядке. **Не live-установщик, не VM/reboot recovery.**

```bash
node scripts/dns-networkd-lab.mjs --coupled-journal \
  --systemd-dir=/absolute/path/to/extracted/lib/systemd \
  --dnsmasq=/absolute/path/to/dnsmasq

MESHPN_SYSTEMD249_DIR=/absolute/path/to/extracted/lib/systemd \
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run test:dns-coupled-real
npm run test:dns-coupled
```

Обычный пользователь, без sudo; tools и изоляция как в [networkd-стенде](dns-networkd-lab.md).
Нельзя совместить `--coupled-journal` с `--link-journal`: это два отдельных
ограниченных набора. Бюджет coupled launcher — 240 секунд, контроллера — 30 секунд.
Ни SSH, ни host DNS/firewall/routes не используются.

## Транзакция

Главный `journal.json` связывает direction/phase/level/pending, исходное состояние
нового link, порт adapter и контекст с дочерним `link/journal.json`. Дочерний журнал
использует ранее проверенный [owned-link lifecycle](dns-owned-link-journal.md).
У обоих одинаковые id/name/boot ID/namespace/bus ID/unique resolved owner; после
создания сверяется ifindex. Оба журнала записаны до первой kernel mutation.
Missing/corrupt child journal не разрешает создать второй интерфейс. Дочерний
контроллер не снимает guard; право снять его остаётся только у координатора.
Оба файла используют bounded private reader и fsync/rename/fsync-directory writer.

Порядок включения:

1. Guard, проверка adapter, создание/маркировка пустого link.
2. Явный `DefaultRoute=false` (даже если автоматическое значение уже false).
3. `addrgenmode=none`, адрес fixture `192.0.2.1/32`, UP.
4. DNSEx → loopback adapter, Domains → `~.`, DefaultRoute → true.

IPv6 link-local на новом интерфейсе не появляется за счёт отдельной настройки
addrgenmode до UP. Это не поддержка IPv6 VPN или полная IPv6 DNS traffic matrix.

Перед каждым шагом сохраняется intent, после setter сверяется read-back и
сохраняется ACK. После аварии разрешено только предыдущее либо ожидаемое следующее
состояние pending-шага. Другие адреса, addrgenmode, DNS/domains, метки или ifindex —
конфликт, без setters и без отката чужих изменений.

`disable` сначала сохраняет направление restore, затем снимает настройки в
обратном порядке, возвращает пустое DOWN-состояние и прежний addrgenmode, удаляет
принадлежащий координатору link. Guard снимается **после** подтверждённого удаления.
Uplink networkd не перезаписывается: после disable действует актуальная DHCP-
конфигурация, а не снимок DNS uplink при старте. Частичный apply можно отключить.
Отключение не требует доступного exit; recover в направлении apply требует
прежнего adapter port и успешной проверки UDP/TCP DNS через exit.

Recovery продолжает последнюю durable direction: незакоммиченный restore-intent
не считается разрешением на отключение. Для повторного disable нужна явная команда.
Новый boot/bus/daemon owner автоматически не принимается.

## Границы проверки

Модельная матрица проверяет intent/set/ACK каждого шага в обоих направлениях,
fsync/rename, частичный disable, конфликты, отказ adapter и потерю child journal.
Реальная матрица использует controller SIGKILL на 16 совместных границах и
один SIGKILL после guard до журнала; отдельно проверяет lock conflict и отказы:
missing/corrupt journal, foreign domains/address, exit-down, stale boot ID.
На восстановленном активном link проверяется настоящий UDP/TCP DNS через
adapter → exit → DoH fixture, а также локальный запрет cloud QNAME. После disable
проверяется текущий DHCP-DNS. Защитные правила проверяются для IPv4/IPv6 UDP/TCP.

Это авария child-контроллера журнала. Namespace supervisor и backend RPC
переживают его; здесь не проверяются падение supervisor, VM reboot, power loss,
перезапуск всего systemd/resolved или долгий live-пилот. Fixed fixture address
не является адресным планом реального VPS. Нет гарантии против root/CAP_NET_ADMIN
противника или атомарного kernel compare-and-swap.

`coupledJournal.dnsSettingsCoupled=true` относится к этой отдельной матрице.
Верхнее `durableJournalTested=false` пока относится к исходным 11 DHCP-сценариям,
которые запускаются перед ней и сохраняют прежний in-memory backend.

Следующий этап — systemd lifecycle и reboot/power-loss для нового координатора
в VM, затем интеграция системного resolver Radxa и согласованные пользовательские
пилоты. DNS v1 не закрывается только этим namespace-тестом.
