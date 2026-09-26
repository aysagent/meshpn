# VPS 2: resolved 249, networkd и настоящий DHCP

Статус: изолированный namespace-стенд, **не установщик DNS на VPS**.
На 2026-09-26: **11/11 проверок PASS** с Ubuntu `249.11-0ubuntu3.22` и dnsmasq 2.90.
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

Дополнительный `--link-journal` запускает после основной матрицы
[журнал пустого owned DNS-link](dns-owned-link-journal.md): 18 SIGKILL контроллера,
конфликты и освобождение ресурсов. Это пока отдельный слой, не recovery основной
DNS-транзакции; её `durableJournalTested` остаётся false.

Альтернативный `--coupled-journal` проверяет уже [совместный координатор](dns-coupled-journal.md)
link/address/UP/resolved: 17 controller SIGKILL, восстановление защищённого DNS,
конфликты, exit-down и обратный disable. Режимы journal взаимоисключающие;
coupled имеет бюджет 240 секунд. Верхние 11 проверок сохраняют in-memory backend,
результат новой матрицы выделен в `coupledJournal`.

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
7. DHCP renew удаляет cloud domains; прежние cloud-имена отклоняет adapter до DoH.
8. DHCP renew заменяет domains на `changed.internal`; прежние cloud-имена по-прежнему
   отклоняются, публичный UDP/TCP DNS продолжает работать.
9. Отказ/возврат exit без прямого DNS fallback.
10. Чужая правка owned link не затирается, guard сохраняется.
11. Disable возвращает путь через текущий DHCP-DNS; UDP/TCP positive controls.

В расширенном прогоне требуется минимум пять DHCP ACK; protected baseline queries=0,
final processes=1/zombies=0. После удаления/замены domains увеличивается именно
`policyDenied`, а DoH bodies/exit attempts и direct DNS observer counts не растут.
Облачные TCP lookup с сохранёнными domains могут завершаться ограниченным
таймаутом клиента: это явно `blockedLookupDeadlines`, **не DNS error response**.
Host launcher ограничивает весь прогон 120 секундами; диагностика демонов bounded.
После завершения удаляются только собственные временные файлы стенда.

Private `/run` скрывает host bus/NSS sockets; синтетические passwd/group/NSS,
resolv.conf и systemd config перекрываются mount-ами, host inode не редактируются.
Свежий sysfs read-only, container marker существует только в private `/run`.
Namespace-local kernel sysctl networkd в этом режиме не управляются; предупреждения
о невозможности их менять не выдаются за проверку sysctl-интеграции.

## Политика внутренних имён и оставшиеся границы

Adapter запускается с явной [QNAME deny-policy](dns-exit-adapter.md#явная-политика-внутренних-имён)
для `ru-central1.internal` / `auto.internal`. Пока более специфичные domains
сохраняются на `eth0`, direct DNS блокирует OUTPUT guard. После их удаления или
замены DHCP-сервером запрос попадает через `~.` в adapter и получает локальный
`REFUSED`, не отправляется в DoH. Это проверяется через настоящий DHCP Renew,
runtime Domains resolved и счётчики adapter/exit/resolver, без подделки lease.
Политика покрывает перечисленные QNAME suffixes; `changed.internal` не добавляется
автоматически. Не обещает фильтрацию upstream recursion/CNAME/EDNS и всех возможных
внутренних имён. Встроенный список здесь — выбор fixture, не live-настройка VPS 2.

Отдельный durable ownership/journal пустого link проверен опцией `--link-journal`,
связка с address/UP и DNS-settings — опцией `--coupled-journal`.
Следующий этап — lifecycle нового координатора в VM. Нельзя ни добавлять прямое
исключение, ни молча разрешать публичный DNS для cloud-имён. Live-политика ещё
не согласована. Оставшиеся установщик/откат и пилоты — в [матрице](dns-client-matrix.md).

Здесь нет reboot/power-loss проверки новых координаторов, live VPS, полноценного Ubuntu 22.04 rootfs,
независимого uplink pcap, IPv6 DNS traffic matrix (IPv6 guard только установлен),
TUN/data plane или общего VPN kill-switch. DNS v1 не объявляется завершённым.
