# VPS 2: resolved 249, networkd и настоящий DHCP

Статус: изолированный namespace-стенд, **не установщик DNS на VPS**.
На 2026-09-26: **9/9 проверок PASS** с Ubuntu `249.11-0ubuntu3.22` и dnsmasq 2.90.
В пользовательском отчёте была `.21`: проверена ветка 249 с более новым Ubuntu
patchlevel, не идентичный образ VPS. Host DNS files и forwarding не изменены.

```bash
node scripts/dns-networkd-lab.mjs \
  --systemd-dir=/absolute/path/to/extracted/lib/systemd \
  --dnsmasq=/absolute/path/to/dnsmasq

MESHPN_SYSTEMD249_DIR=/absolute/path/to/extracted/lib/systemd \
MESHPN_DNSMASQ=/absolute/path/to/dnsmasq npm run test:dns-networkd-real
npm run test:dns-networkd
```

Запуск обычным пользователем Linux, без sudo. Нужны user/net/PID/mount/UTS
namespaces, Node 22+, iproute2, mount, iptables/ip6tables, openssl, dbus-daemon,
busctl и getent. Runner ничего не скачивает и не устанавливает. Tools directory
должен содержать доверенные `systemd-resolved`, `systemd-networkd` и
`libsystemd-shared-249.so`, извлечённые из одного пакета **вне системных каталогов**.
`LD_LIBRARY_PATH` задаётся только для этих демонов/их preflight, не глобально.
У networkd 249 нет `--version`: проверяются зависимости на shared-249 и SHA256;
версия resolved проверяется отдельно. JSON содержит версии и хеши инструментов.

Для выполненного прогона пакет `systemd_249.11-0ubuntu3.22_amd64.deb` скачан
из официального Ubuntu jammy-updates после `apt-get update` с отдельным
`APT_CONFIG` (все State/Cache/Log и sources — в `/tmp`, signed-by системным
Ubuntu archive keyring). SHA256 архива сверена с этими подписанными metadata:
`7c7f94c8baf06ae99221537fc556edf302c597b2d7c93ea4b09986aaae71c253`.
Использовался только `apt-get download` и `dpkg-deb -x`, не установка пакета.
Хеш не заменяет проверку происхождения при подготовке других инструментов.

## Почему отдельный DNS-интерфейс

Resolved 249 отказывает `SetLinkDNSEx` на networkd-managed интерфейсе;
[проверка в исходниках](https://github.com/systemd/systemd/blob/v249/src/resolve/resolved-link-bus.c)
подтверждена настоящим вызовом D-Bus в стенде. Прежний owned-link backend
тестировался на unmanaged dummy, поэтому его PASS не разрешал захват `eth0`.

Здесь networkd сохраняет управление `eth0`, адресом, маршрутами, DHCP-DNS и
cloud search domains. Backend управляет только отдельным dummy `vpndns`:
loopback adapter и routing domain `~.`. Никакого TUN. Запросы обычных публичных
имён проходят через настоящий adapter → combo exit → TLS DoH fixture.
При disable этот dummy удаляется под guard, а затем защита явно снимается:
используется **актуальный DHCP-DNS**, не сохранённый при старте адрес uplink.
Это эксперимент выбора архитектуры, ещё не durable host backend.

## Изоляция и проверки

Клиент и облачный DHCP/DNS-сервер находятся в **разных network namespaces**,
соединены veth. Доступа к внешней сети нет; все IP из конфигурации — адреса
локальных fixtures. Сервер использует настоящий dnsmasq, клиент — networkd 249.
Начальный DISCOVER/OFFER/REQUEST/ACK, unicast Renew через networkd D-Bus и новая
аренда после Reconfigure подтверждаются серверными ACK и runtime lease networkd.
Не подделываются lease/state файлы networkd или его D-Bus свойства.

1. Реальный DHCP baseline: `10.129.0.18`, DNS `10.129.0.2`, два cloud domain.
2. Отказ resolved менять networkd-owned `eth0`, исходные настройки сохранены.
3. Публичный UDP/TCP DNS через принадлежащий стенду `vpndns`, без uplink takeover.
4. Внутренние имена недоступны, ни cloud DNS, ни DoH fixture их не получают.
5. DHCP renew меняет DNS на `10.129.0.3`; VPN DNS не меняется.
6. Networkd Reconfigure с новым DHCP обменом сохраняет VPN DNS.
7. Отказ/возврат exit без прямого DNS fallback.
8. Чужая правка owned link не затирается, guard сохраняется.
9. Disable возвращает путь через текущий DHCP-DNS; UDP/TCP positive controls.

В прогоне: три DHCP ACK, два DISCOVER, три REQUEST; protected baseline queries=0,
final processes=1/zombies=0. Шесть облачных TCP lookup завершены ограниченным
таймаутом клиента: это явно `blockedLookupDeadlines`, **не DNS error response**.
Host launcher ограничивает весь прогон 120 секундами; диагностика демонов bounded.
После завершения удаляются только собственные временные файлы стенда.

Private `/run` скрывает host bus/NSS sockets; синтетические passwd/group/NSS,
resolv.conf и systemd config перекрываются mount-ами, host inode не редактируются.
Свежий sysfs read-only, container marker существует только в private `/run`.
Namespace-local kernel sysctl networkd в этом режиме не управляются; предупреждения
о невозможности их менять не выдаются за проверку sysctl-интеграции.

## Важная незакрытая граница: внутренние имена

Отказ cloud DNS в этой матрице зависит от сохранённых более специфичных
`ru-central1.internal` / `auto.internal` на `eth0` и OUTPUT guard. Это **не
самостоятельная deny-policy**. Если DHCP уберёт эти domains, одно `~.` может
отправить такие имена в публичный DoH. Поэтому данный fixture нельзя переносить
на live-клиент как готовую защиту внутренних имён.

Следующий ограниченный этап: явная политика внутренних доменов перед DoH,
проверка удаления/замены DHCP domains; затем durable ownership/journal для
создания/удаления VPN DNS-link и lifecycle в VM. Нельзя ни добавлять прямое
исключение, ни молча разрешать публичный DNS для cloud-имён. Live-политика ещё
не согласована. Оставшиеся установщик/откат и пилоты — в [матрице](dns-client-matrix.md).

Здесь нет reboot/SIGKILL-журнала, live VPS, полноценного Ubuntu 22.04 rootfs,
независимого uplink pcap, IPv6 DNS traffic matrix (IPv6 guard только установлен),
TUN/data plane или общего VPN kill-switch. DNS v1 не объявляется завершённым.
