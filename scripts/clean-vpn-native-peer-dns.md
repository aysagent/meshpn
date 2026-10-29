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
DNS labels длиной 1–32 символа, начиная с буквы; адреса — `10.99.0.2..254`.
Дубли имён/адресов запрещены, в том числе среди отозванных записей.

- Активный клиент: A и PTR со стабильным адресом, TTL 5 секунд.
- AAAA, HTTPS, SVCB и прочие обычные типы для известного имени: NOERROR/NODATA.
- Неизвестный, отозванный клиент или вложенное имя: NXDOMAIN с SOA и TTL 5.
- Вопрос вне обслуживаемых зон: REFUSED, без recursion и upstream.
- Нечитаемый/повреждённый реестр: SERVFAIL для приватных зон. Старые записи
  после отзыва не сохраняются в памяти как fallback.
- Вопросы обновления/transfer/ANY и malformed DNS не обслуживаются.

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

Следующий шаг — opt-in интеграция именно этой зоны с выбранным backend на exit,
затем с DNS клиентов. Существующий native DNS relay пока не менялся.
`mpn.local` для USB-админки остаётся отдельным mDNS-именем.

## Приёмка

```sh
node --test scripts/test-native-peer-dns.mjs
```

Тесты проверяют UDP/TCP, фрагментацию/pipelining, A/PTR/NODATA/NXDOMAIN,
EDNS/BADVERS, binary-label boundary, atomic rename/revoke/corruption,
ошибки разрешений, symlink, лимиты соединений/запросов и освобождение портов.
Это не проверка системной DNS-интеграции или межклиентской маршрутизации.
