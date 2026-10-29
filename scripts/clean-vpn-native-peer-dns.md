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
применённые или ожидающие rollback назначения.

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
Интеграция с DNS клиентов остаётся отдельным этапом. Существующий native DNS relay пока не менялся.
`mpn.local` для USB-админки остаётся отдельным mDNS-именем.

## Приёмка

```sh
node --test scripts/test-native-peer-dns.mjs
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
