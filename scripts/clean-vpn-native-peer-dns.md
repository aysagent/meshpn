# Имена клиентов в приватной зоне .mpn

`clean-vpn-native-peer-dns.mjs` обслуживает имена `laptop.mpn`, `radxa.mpn`
и обратную зону `0.99.10.in-addr.arpa` из реестра управления клиентами.
Это отдельный opt-in control-plane resolver; он не меняет DNS, маршруты,
firewall, права межклиентского доступа или действующий VPN.

## Реестр и ответы

Вход — приватный `registry.json` менеджера клиентов:

```json
{
  "version": 1,
  "revision": 1,
  "clients": [
    { "name": "laptop", "ipv4": "10.99.0.3", "revoked": false },
    { "name": "old-phone", "ipv4": "10.99.0.4", "revoked": true }
  ]
}
```

Менеджер хранит дополнительные поля, включая пути ключей. Resolver их не
использует и не возвращает. Требуются абсолютный путь, обычный файл с режимом
0600 и доверенные родительские каталоги без symlinks. Registry и его родители
принадлежат root или пользователю процесса; не допускается запись посторонними.
Размер ограничен 128 KiB, число записей — 254. Имена — одиночные lowercase
DNS labels длиной 1–63 символа, начиная с буквы или цифры; адреса — `10.99.0.2..254`.
Дубли имён/адресов запрещены, в том числе среди отозванных записей.

- Активный клиент: A и PTR со стабильным адресом, TTL 5 секунд.
- AAAA, HTTPS, SVCB и прочие обычные типы для известного имени: NOERROR/NODATA.
- Неизвестный, отозванный клиент или вложенное имя: NXDOMAIN с SOA и TTL 5.
- Вопрос вне обслуживаемых зон: REFUSED, без recursion и upstream.
- Нечитаемый/повреждённый реестр: SERVFAIL для приватных зон. Старые записи
  после отзыва не сохраняются в памяти как fallback.
- Вопросы обновления/transfer/ANY и malformed DNS не обслуживаются.

Пока рядом есть `transaction.json` незавершённой операции менеджера, resolver
отвечает SERVFAIL для приватных зон. Это не позволяет публиковать ещё не
применённые или ожидающие rollback назначения. После последней проверки
маркера resolver сверяет inode текущего пути с прочитанным FD: завершившийся
между чтением и ответом rollback не может опубликовать временный snapshot.
Atomic replacement во время чтения даёт SERVFAIL, успешный commit сохраняет
прочитанный inode и разрешает ответ.

Registry перечитывается перед каждым допущенным запросом. Atomic rename
менеджера виден без restart. Если внешняя программа пишет файл неатомарно,
временный parse failure даёт SERVFAIL, а не частично обновлённую зону.
Запись DNS означает назначенный адрес, **не доказательство подключения**.
Отключённый клиент сохраняет имя; отозванный клиент исчезает из зоны.
Кэш другого resolver может удерживать старый ответ в пределах TTL.

## Проверить и запустить отдельно

```sh
node scripts/clean-vpn-native-peer-dns.mjs check \
  --registry=/var/lib/clean-vpn/clients/registry.json

node scripts/clean-vpn-native-peer-dns.mjs run \
  --registry=/var/lib/clean-vpn/clients/registry.json --port=1055

dig @127.0.0.1 -p 1055 laptop.mpn A
dig @127.0.0.1 -p 1055 -x 10.99.0.3 +tcp
```

UDP и TCP слушают **только 127.0.0.1**. CLI не разрешает порт ниже 1024;
не открывает публичный resolver и не занимает системный порт 53.
Границы: 4096 байт запроса, 16 TCP-клиентов, 32 запроса на TCP-соединение,
5 секунд idle, 8196 байт входного буфера, общий token bucket 256 запросов/сек
с burst 512. UDP send queue также ограничена. Нехватка бюджета означает drop
UDP либо закрытие TCP. Это локальный служебный resolver, не high-QPS DNS server.

## Systemd и подключение к системному DNS

Команда печатает unit; ничего не устанавливает и не активирует:

```sh
node scripts/clean-vpn-native-peer-dns.mjs unit \
  --registry=/var/lib/clean-vpn/clients/registry.json \
  --node=/usr/bin/node \
  --script=/opt/meshpn/scripts/clean-vpn-native-peer-dns.mjs
```

Используются actual absolute paths. Unit работает с пустым capability set,
read-only host filesystem, отдельным `/tmp`, ограничениями FD/tasks/memory.
В комплекте должны быть script и его `lib/native-peer-dns.mjs`,
`lib/lab-dns-wire.mjs`. Registry должен быть доступен для чтения; ключи resolver
не открывает. Остановка закрывает UDP/TCP и текущие запросы.

Сам запуск ещё **не делает `getent hosts laptop.mpn` рабочим на exit**:
системный resolver должен направлять зоны `mpn` и `0.99.10.in-addr.arpa`
в этот listener. Подключение зависит от владельца системного DNS и остаётся
отдельной явной операцией. Нельзя подменять весь системный DNS этим listener:
внешние имена он намеренно не разрешает. Пока zone routing не подключён,
используйте явный `dig @127.0.0.1 -p 1055`; обычный запрос к прежнему DNS ещё
может уйти наружу. На физическом VPS ничего не устанавливалось.

Для systemd-resolved имеется явный владелец scope, описанный ниже.
Native DNS клиентов также поддерживает приватную зону через opt-in exit bridge,
описанный ниже. Для имён на самом exit scope resolved нужен отдельно.
`mpn.local` для USB-админки остаётся отдельным mDNS-именем.

## Приёмка

```sh
node --test scripts/test-native-peer-dns.mjs scripts/test-native-peer-dns-transactions.mjs
```

Тесты проверяют UDP/TCP, фрагментацию/pipelining, A/PTR/NODATA/NXDOMAIN,
EDNS/BADVERS, binary-label boundary, atomic rename/revoke/corruption,
ошибки разрешений, symlink, лимиты соединений/запросов и освобождение портов.
Системная интеграция проверяется отдельным изолированным тестом ниже;
межклиентская маршрутизация не открывается.

## Opt-in scope для systemd-resolved на exit

`clean-vpn-native-peer-dns-zone.mjs` предназначен для Linux root с уже работающим
systemd-resolved. Он создаёт отдельный dummy-интерфейс со случайным именем,
MAC и ownership alias, назначает свободный `169.254.255.53/32`, устанавливает
только для этого интерфейса DNS `127.0.0.1:1055`, route-only domains `~mpn` и
`~0.99.10.in-addr.arpa`, `DefaultRoute=false`. Обычные домены продолжают
использовать исходный DNS. Loopback-интерфейс не подходит для такого scope;
UP dummy с собственным /32 проверен на настоящем resolved.

Не редактируются `/etc/resolv.conf`, NSS, существующие интерфейсы, их DNS,
маршрут по умолчанию, forwarding и firewall. Ядро добавляет только маршруты
собственного /32. Занятый адрес/покрывающий маршрут или чужая такая же/вложенная
DNS-зона приводят к отказу. Другой свободный link-local /32 задаётся через
`--address`; port должен совпадать с private resolver.

Сначала просмотр без изменений:

```sh
node scripts/clean-vpn-native-peer-dns-zone.mjs plan \
  --directory=/var/lib/clean-vpn-mpn-zone
node scripts/clean-vpn-native-peer-dns-zone.mjs unit \
  --directory=/var/lib/clean-vpn-mpn-zone
```

Перед явным apply убедитесь, что private resolver отвечает, обычный системный
DNS действительно обслуживается resolved и приложение пользуется системным
DNS. Затем на выбранном **exit**, не на MacBook:

```sh
sudo node scripts/clean-vpn-native-peer-dns-zone.mjs apply \
  --directory=/var/lib/clean-vpn-mpn-zone
getent ahostsv4 laptop.mpn
getent hosts 10.99.0.3
sudo node scripts/clean-vpn-native-peer-dns-zone.mjs status \
  --directory=/var/lib/clean-vpn-mpn-zone
```

Private state directory создаётся 0700, journal 0600 записывается с fsync
до первой сетевой операции; flock предотвращает параллельное изменение.
После сбоя повторный apply продолжает только интерфейс с совпавшими
boot/net namespace, именем, MAC, ifindex, alias, адресом и DNS-настройками.
Чужие изменения не перезаписываются. Ошибка ownership требует разбора,
не принудительного удаления.

Команда `unit` печатает сервис `watch`: нужны полное дерево `scripts/lib`,
доверенные абсолютные пути и заранее созданный private state directory.
Вывод можно установить в отдельный unit после review. Watch каждые 5 секунд
проверяет scope, восстанавливает пустые настройки после смены процесса
resolved, прекращает работу при конфликте. Unit получает только
CAP_NET_ADMIN; READY отправляется после проверки DNS readback. Повторные
проверки не переписывают journal. Unit не включает/перезапускает VPN.

**Остановка watch или DNS-daemon сохраняет scope.** При отказе private DNS
запросы `.mpn` завершаются ошибкой, не переключаются на публичный upstream.
SIGKILL watch допускает автоматический restart с тем же интерфейсом.
Для явного удаления сначала остановите установленный watch-unit, затем:

```sh
sudo node scripts/clean-vpn-native-peer-dns-zone.mjs remove \
  --directory=/var/lib/clean-vpn-mpn-zone
```

Remove удаляет только проверенный собственный интерфейс и journal. Остальной
DNS остаётся исходным. После remove приватный routing scope отсутствует:
обычные `.mpn` запросы снова могут попасть в исходный DNS; это сознательное
отключение интеграции, не режим аварийного fallback.

После reboot сетевой scope исчезает; watch создаёт новый по прежнему journal.
Защита действует после READY и пока scope существует. Для потребителя, который
не должен отправлять `.mpn` до READY, нужна явная systemd ordering/dependency;
универсальный boot leak guard здесь не объявляется. DoH приложений обходит
системный DNS. Чужой процесс с root/CAP_NET_ADMIN может удалить scope; монитор
это обнаружит, но не является firewall. Имена не предоставляют доступ к
клиенту и не доказывают, что клиент сейчас подключён.

Механика routing domains и приоритет наиболее специфичной зоны описаны в
[systemd RESOLVED-VPNS](https://github.com/systemd/systemd/blob/main/docs/RESOLVED-VPNS.md)
и [resolvectl](https://www.freedesktop.org/software/systemd/man/255/resolvectl.html).

### Изолированная приёмка scope

```sh
node --test scripts/test-native-peer-dns-zone.mjs
CVPN_DISPOSABLE_HOST_NET=1 node scripts/test-native-peer-dns-resolved.mjs
```

Второй тест отказывается работать вне специально помеченного disposable
Linux systemd-стенда без NIC/default route; это не команда для VPS/Radxa.
В образе нужны systemd-resolved, libnss-resolve, dnsutils, iproute2, util-linux,
Node. Marker `/etc/meshpn-admin-disposable-lab` имеет значение
`isolated-admin-lab-v1`; не создавайте его на рабочей системе.

Результат systemd 255: 15/15 unit-тестов scope без пропусков, 23/23 реальных
проверок. Проверены `getent`, UDP/TCP через stub, A/PTR, hot rename/revoke,
NXDOMAIN и SERVFAIL без публичного fallback, SIGKILL обоих процессов,
restart resolved, recover после создания интерфейса, ownership collision,
notify READY, точная неизменность чужого DNS после apply/remove и обычный
public DNS при отказавшем private daemon. Дополнительный public upstream
считает все запросы и имеет успешный positive control; сеть контейнера
изолирована от WAN. `/etc/resolv.conf` и NSS сравниваются побайтно.

## Native client → tunnel → exit registry

При `dns:true` native client всегда распознаёт полные DNS labels зоны `mpn`
и `0.99.10.in-addr.arpa` и отправляет эти запросы только к `10.99.0.1:1055`
через свой TUN. UDP/TCP sockets сохраняют `SO_BINDTODEVICE` и `SO_MARK`.
Публичные `1.1.1.1/8.8.8.8:53` используются только для остальных зон.
Если приватный exit resolver отсутствует, недоступен или возвращает SERVFAIL,
клиент возвращает SERVFAIL; приватные запросы не переходят к public upstream.
Malformed/compressed query envelopes отбрасываются; binary labels, точки и
escape-последовательности внутри одного label дают FORMERR без forwarding.
`Laptop.MPN` распознаётся как приватное имя; `mpn.example` не является зоной.

На exit включите **явно** `private_peer_dns: true` в packet config; для combo
это `boring.private_peer_dns`. На client поле запрещено. Соответствующая опция
сетевого профиля должна совпадать: [scoped network rules](clean-vpn-native-private-dns-network.md).
Включение/выключение bridge требует restart, список peers обновляется SIGHUP.

Bridge слушает только `10.99.0.1:1055` и закреплён `SO_BINDTODEVICE` к exit TUN.
Принимаются только текущие IP из аутентифицированного peer registry engine;
входные IP-пакеты дополнительно проходят обычную проверку привязки source к
ключу сессии. Он отправляет только приватные DNS-зоны к `127.0.0.1:1055`, где
работает Node registry resolver. Остальные зоны получают REFUSED. Listener
не публикуется на WAN; profile допускает только TUN→1055 и ответы established
обратно в TUN. Loopback resolver, engine и registry должны быть в одном
network namespace. Scope systemd-resolved для этого пути не требуется.

Ограничения bridge: 16 concurrent jobs суммарно, максимум 4 на один peer,
256 admissions/сек суммарно и 64/сек на peer; TCP — максимум 32 запроса на
соединение и 10 секунд lifetime, query ≤4096 bytes, upstream deadline 1.2s.
SIGHUP заменяет allowlist вместе с peers; удалённые IP теряют право на новые
запросы, pending TCP/UDP jobs проверяют отзыв при ожидании/отправке и закрываются.
Backend registry дополнительно блокирует ответы при незавершённой транзакции.

Обычный `getent ahostsv4 laptop.mpn` на client работает, если DNS клиента уже
подключён к native stub через существующий owner/guard. DNS-пакеты приложений
напрямую к внешним DNS перехватываются текущим DNS DNAT; DoH приложений этот
механизм не охватывает. Client-to-client forwarding по-прежнему запрещён:
разрешить имя другого peer не означает разрешить подключение к нему.

Для контейнера возможен trusted control-plane resolver sidecar с
`network_mode: service:vpn`, без published ports и capabilities, с read-only
manager directory. Mount одного `registry.json` использовать нельзя: atomic
rename оставит bind-mount на старом inode. Resolver должен видеть также sibling
`transaction.json`. Полный directory может содержать ключи: resolver не читает
их, но такой sidecar входит в доверенную control-plane область. Отдельная
sanitized publication view потребует согласованного transaction lifecycle.

Проверки:

```sh
CVPN_BUILD=/path/to/linux/build node --test scripts/test-native-dns.mjs
CVPN_DISPOSABLE_HOST_NET=1 node scripts/test-native-peer-dns-tunnel.mjs
```

Последний тест допускается только в описанной выше NIC-less лаборатории.
Выполнены 11/11 реальных проверок на новом production engine: native TLS/TUN,
клиентский NSS и PTR, оба public positive controls, REFUSED для попытки recursion,
NXDOMAIN/SERVFAIL без public fallback, hot registry revoke, остановка registry,
WAN и поддельный разрешённый source IP, native SIGHUP revoke и полная очистка.
Применяются сгенерированные production `nativeNetworkPlan` firewall rules,
а не разрешение всего трафика. Unit relay отдельно проверяет pending TCP revoke,
per-peer saturation и освобождение FD. Никакие физические узлы не обновлялись.

### Ограниченный fault/soak

Для такого же изолированного стенда доступен один прогон 300–600 секунд:

```sh
CVPN_DISPOSABLE_HOST_NET=1 CVPN_PEER_DNS_SOAK_SECONDS=300 \
  node scripts/test-native-peer-dns-tunnel.mjs
```

Он запускает двух реальных TLS/TUN клиентов, держит четыре TCP-запроса одного
peer и проверяет DNS второго, затем повторяет UDP/TCP на фоне atomic rename,
revoke, pending transaction, повреждения registry и остановки/запуска backend.
Для каждого этапа проверяется ожидаемый A/NXDOMAIN/SERVFAIL, счётчик public
upstream не должен увеличиваться. В конце сравниваются FD, threads и RSS
обоих клиентов и exit; все процессы/netns/interface удаляются.

Прогон 2026-10-30: 301 секунда, 633 раунда, минимум 17 724 приватных запроса,
64 restart registry backend, **0 private→public fallback**. За этот прогон:

| Процесс | FD до → после | Threads до → после | RSS KiB до → после |
| --- | --- | --- | --- |
| Exit | 9 → 9 | 2 → 2 | 6476 → 6532 |
| Client 1 | 7 → 7 | 2 → 2 | 6376 → 6424 |
| Client 2 | 7 → 7 | 2 → 2 | 6356 → 6412 |

Сэмплы берутся после полного раунда; это проверка восстановления ресурсов,
не измерение мгновенного максимума под пиковым количеством jobs. Native binary
в этом soak соответствовал `a9cb8bd`. Во время параллельного аудита найден и
исправлен inode/rollback race (`09dc688`); новый resolver отдельно прошёл
23/23 Linux unit/cross-process проверки и повтор коротких реальных TLS/TUN и
systemd-resolved матриц. Этот тест не заменяет длительную эксплуатацию.

Граница изоляции: network namespace ограничивает IP-сокеты, но не доступ к
общим Unix sockets. NSS `resolve` или приложение, обращающееся к host
systemd-resolved через общий `/run`/system bus, может поручить DNS процессу
вне namespace. Для контейнера не монтируйте host resolver/D-Bus sockets;
для standalone netns нужен явный владелец локального DNS/NSS. Один `ip netns
exec` при общем host `/run` не доказывает отсутствие DNS-обхода. В лаборатории
клиентский NSS явно направлен в `dns` через отдельный `/etc/netns/<name>`
mount, а системные файлы родительского namespace не меняются.

Отдельная проверка `test-native-runtime-dns-dnat-linux.mjs` проверяет узкое
OUTPUT-разрешение DNS DNAT: оно требует `--dst-type LOCAL`, поскольку до
создания TUN его будущий IP ещё не принадлежит клиенту. Иначе переведённый
пакет мог бы уйти через WAN default route. В NIC-less disposable лаборатории
тест запускается с `CVPN_DNS_DNAT_WAN_TEST=1`; raw AF_PACKET observer находится
только в синтетическом WAN namespace. На nft и legacy прошли UDP/TCP до
создания TUN, рабочий локальный stub после создания TUN и повтор после удаления
TUN: **0 DNS-пакетов на WAN** во всех этих фазах. Положительный контроль до
guard доказывает достижимость WAN-получателя; обращения к on-link resolver
при работающем TUN успешно попадают в локальный stub. Это проверка runtime
owner, не универсальный аудит произвольной host firewall/NSS-конфигурации.

### Native reload одновременно с DNS workers

Отдельный opt-in для того же NIC-less disposable стенда (по умолчанию выключен):

```sh
CVPN_DISPOSABLE_HOST_NET=1 CVPN_PEER_DNS_RELOAD_ROUNDS=6 \
  CVPN_BUILD=/native node scripts/test-native-peer-dns-tunnel.mjs
```

Допустимо 2–16 раундов. Два частично переданных TCP DNS запроса удерживают
реальные native workers; тест подтверждает их наличие через число threads.
Параллельно идут UDP/TCP private DNS от обоих клиентов и ICMP через packet
ветку от второго клиента. Native exit получает SIGHUP с перестановкой
неизменённых peers, затем удалением первого peer и заменой его ключа.

После удаления peers тест проверяет освобождение удержанных DNS workers ещё
до закрытия клиентских сокетов. Старый ключ больше не проходит discovery,
новый клиент с новым ключом снова резолвит имена. Exit и второй клиент сохраняют
PID, его DNS/ICMP продолжают работать; публичный DNS не получает private запросов.
После восстановления исходного тестового ключа выполняется обычная финальная
проверка полного revoke и cleanup. Все native журналы дополнительно проверяются
на сообщения ASAN/UBSAN/TSAN, включая ожидаемые отрицательные сценарии.

Нормальный engine `48df7b…` прошёл 12 проверок с шестью раундами и девятью
подтверждёнными reload в этом блоке. Это проверка функциональности тестового
сценария; отдельный запуск под TSAN нужен для проверки потоковых гонок.

Тот же сценарий затем прошёл 12/12 на полном engine, собранном с TSAN
(`56d15d8…`), после замены глобальных сигнальных flags на lock-free atomics.
Использовались `halt_on_error=1:exitcode=66` и отдельный `log_path`; после
остановки всех процессов проверены отсутствие файлов отчётов и предупреждений
TSAN. Библиотеки зависимостей не инструментированы. Лимиты прикладных threads
в этом сценарии не ослаблялись. Это отдельный результат от нормального прогона
и не заменяет длительный soak или проверку всех возможных гонок.
