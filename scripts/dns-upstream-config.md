# DNS upstream/bootstrap: конфигурация и pinned route exit

Есть offline checker, проверка на стенде и **явный opt-in pinned route на exit**.
Checker ничего не запускает; флаг exit применяется только при отдельном запуске
VPN оператором. Resolver не выбирается автоматически, DNS клиента/системы не
перенастраивается. При разработке работающий VPN, TUN, firewall и mesh не менялись.

```bash
npm run dns:check-upstream -- --config=/path/to/upstream.json
npm run test:dns-upstream-config
```

CLI читает только указанный regular non-symlink JSON-файл ≤128 KiB. FIFO/device/
directory/symlink отвергаются. Ограниченное чтение также защищает от роста файла
между stat/read; нет подгрузки CA по URL/из отдельных файлов. UTF-8 строгий,
duplicate JSON keys (включая escaped equivalents), неизвестные поля и глубина
контейнеров >16 отвергаются. Файл не изменяется, listeners не запускаются.

Успех: одна строка `DNS_UPSTREAM_CONFIG {...}`, `status: validated-offline`,
`runtimeEnabled: false`. Только число адресов/CA, семейства IP и режим доверия;
без hostname, IP, PEM, имени файла или credentials. Ошибка — стабильный
`DNS_UPSTREAM_CONFIG_INVALID`, ненулевой exit, без содержимого файла/stack.

## Формат

[Шаблон](fixtures/dns-upstream.example.json) намеренно содержит невалидный
placeholder IP: его нельзя случайно принять за готовую конфигурацию чужого
resolver. Нужно указать выбранный оператором сервер и реальные согласованные
с ним IP. Валидатор **не** доказывает принадлежность IP имени или доступность.

```json
{
  "schema": 1,
  "transport": "doh",
  "hostname": "resolver.operator.example",
  "port": 443,
  "path": "/dns-query",
  "bootstrap": { "addresses": ["REPLACE_WITH_VERIFIED_PUBLIC_IP"] },
  "trust": { "mode": "bundled" }
}
```

Все семь верхнеуровневых полей обязательны; неожиданные поля не игнорируются.

- `hostname`: одно ASCII DNS-имя, без URL, порта, IP literal, wildcard, trailing
  dot или local/search-domain имени. Unicode предварительно преобразуется
  оператором в корректный ASCII IDNA. Lowercase canonical form используется
  одновременно для TLS SNI, certificate hostname check и HTTP Host. Отдельных
  override для этих трёх значений нет.
- `port`: integer1..65535. При443 HTTP Host — hostname, иначе hostname:port.
  Runtime route подключается только явным флагом ниже. DNS adapter использует
  DoH POST поверх TLS1.3+; exit не терминирует и не проверяет этот TLS/HTTP.
- `path`: простой абсолютный путь ≤256 символов, например `/operator/dns`.
  Без URL, query string, `%` escapes, fragment, dot segments, пустых segments,
  auth/token, URI template. Такие DoH deployments пока не поддерживаются.
- `bootstrap.addresses`: 1..8 явно заданных числовых public-unicast IPv4/IPv6.
  Весь список проходит существующую консервативную exit IP policy; один private/
  loopback/special-use адрес отвергает **всю** конфигурацию. Duplicate/equivalent
  IPv6 удаляются с сохранением порядка. Никакого DNS lookup для bootstrap.
  Список становится immutable snapshot с address/family/port. При opt-in на
  exit connector использует только этот список для configured hostname+port.
- `trust.mode: bundled`: явная копия CA bundle текущей версии Node, не
  автоматически меняющийся OS/default store. Она не расширяется через
  `NODE_EXTRA_CA_CERTS` или default CA overrides. Это следует из семантики
  [Node tls.rootCertificates](https://nodejs.org/download/release/v24.13.0/docs/api/tls.html#tlsrootcertificates).
- `trust.mode: custom`: вместо bundle — `certificates`, массив1..8 PEM строк,
  по одному CA-сертификату ≤16 KiB каждая. Проверяются parsing, CA flag и срок
  действия; ключи, PEM-bundle в одной строке, мусор и пустой trust отвергаются.
  Duplicate CA удаляются. Custom trust **заменяет**, а не расширяет bundled.
  [X509Certificate](https://nodejs.org/docs/latest-v24.x/api/crypto.html#class-x509certificate)
  используется для проверки структуры; это не автоматическое подтверждение
  доверия выбранному CA, его revocation или правильности оператора resolver.

При custom trust обязательна та же проверка TLS hostname. Нельзя разрешить
неверный сертификат, включить direct/system/plaintext fallback или передать
произвольные TLS/HTTP options через JSON. CA validity проверяется при compile,
TLS цепочка и имя — при соединении. Нет автоматической загрузки CRL/OCSP.

## Как это проверено без внешних соединений

`compileDnsUpstream` создаёт публичный immutable contract без I/O.
`dnsUpstreamTlsOptions` выдаёт TLS identity options **без адреса подключения**;
это намеренно не готовый direct-connect клиент. Forged/cloned plain objects
не считаются compiled profiles.

Отдельный `compileLabDnsUpstream` разрешает только IP `127.0.0.1` и дополнительно
имя `localhost`. Это явный JS test API, не поле конфигурации/CLI switch.
Публичный profile нельзя передать как lab target. Lab направляет TCP только
на числовой loopback-порт transparent client; далее идут тот же client/exit и
синтетический HTTPS resolver. Logical Host port/path могут отличаться от
физических ephemeral fixture ports — это **только стендовое отображение**.

Обычные DNS smoke/pcap/soak теперь создают lab profile через этот контракт.
Legacy ca/servername overrides оставлены для старых fault-injection тестов.
Новые real-loopback проверки подтверждают нестандартные Host/path, UDP/TCP
A/AAAA, CA/hostname rejection до получения DNS HTTP body. Certificate check
всегда использует hostname профиля, а не переданный IP/постороннее имя.
После мутации исходного JSON/object поведение уже compiled profile не меняется.

## Opt-in на exit

К обычному запуску `clean-vpn.js` оператор может явно добавить:

```text
--tls-dns-upstream-config=/path/to/upstream.json
```

Только `--role=exit` с `--type=transparent-tls` или `--type=combo-tls`.
Client/другой transport, bare/empty/duplicate/malformed flag и невалидный JSON
отвергаются **до runExit/runClient**, то есть до TUN/NAT/listeners.
Загрузка использует тот же bounded reader, что offline checker; ошибки redacted.
Без флага действует прежняя policy. Этот пакет не запускал флаг на live exit.

Policy создаётся один раз при старте. Файл потом не перечитывается, DNS polling/
hot reload/автоматической ротации нет. Для смены списка нужен отдельно управляемый
restart приложения. Политика общая для enc-SNI sessions этого exit, не per-client.

- Auth/replay admission остаётся **до** выбора адреса. ClientHello/enc-SNI
  metadata не может передать или изменить configured bootstrap-IP.
- Case-insensitive точное hostname + настроенный port → статический список,
  без OS DNS lookup и без расхода DNS pending slots. Заполненный DNS budget
  других routes не блокирует эту route.
- То же hostname на **другом порту запрещено**, а не отправлено в DNS.
  Subdomains/другие hostname не становятся aliases pinned route: для них
  сохраняется обычная destination policy и OS DNS. Это не общая DNS allowlist.
- Private/mixed/special-use candidates не разрешаются даже в operator pin.
  Programmatic loopback exception нельзя сочетать с production pin.
- Используется существующий bounded sequential TCP failover: default общий
  бюджет10 с, non-final attempt250 мс; конкретные retryable TCP ошибки идут к
  следующему IP. Реальный peer IP/port сверяется с выбранным кандидатом.
- После успешного TCP выбора ClientHello отправляется только на выбранный IP.
  TLS/certificate/HTTP/reset после выбора не повторяет DNS request на другом IP.
  Исчерпание списка → `TLS_RELAY_CONNECT_EXHAUSTED`, без DNS, другого resolver,
  direct-client или combo-mux fallback. Abort/deadline останавливает перебор.

Exit использует из профиля только hostname/port/IP для маршрутизации. Полная
конфигурация всё равно валидируется, но CA/name/path/HTTP validation выполняет
**клиент DoH**, не exit. TLS end-to-end; exit не может гарантировать, что внутри
идёт именно DoH, а не другой TLS-трафик к разрешённому endpoint. Это не DPI/ACL
по URL и не отключение OS DNS для остальных назначений.

JS API: `dnsUpstreamExitPolicy(compileDnsUpstream(json))` даёт настоящий
`ExitDestinationPolicy`, передаваемый в `wireTransparentTlsEncSniSession`.
Lab/forged/cloned profiles не допускаются. Низкоуровневый constructor также
повторно валидирует/copies public pin, не доверяя внешним mutable candidates.

## Что ещё не сделано

При запуске **без флага** exit по-прежнему использует OS resolver, в том числе
для DNS endpoint. Checker отдельно не активирует route. Клиентский production
stub ещё не подключён: флаг exit не заставляет OS/приложения отправлять DNS в relay.
Нельзя просто передать первый IP в прямой HTTPS connect клиента: это обойдёт relay.
Следующий пакет — explicit клиентский DNS adapter через числовой exit endpoint,
с согласованными hostname/port/path/CA, без системного DNS переключения и TUN.

Адрес/доверие самого exit тоже требуют отдельной bootstrap-конфигурации.
OS/LAN/IPv6 DNS integration, общий exit DNS, resolver selection, caching/pooling,
secret URL/header support и эксплуатационная ротация IP/CA пока вне пакета.
DNS wire/parser и stub всё ещё лабораторные, поддерживают только IN A/AAAA.

## Проверка на VPS

65 новых регрессий; полный acceptance — два последовательных прогона по
571 Node-тесту (23 файла) +14 Chrome/Firefox сценариев, PASS без skips.
Отдельно6 real DNS pcap/soak lifecycle регрессий PASS уже через новый lab profile.
Изначальный общий запуск при параллельном soak упал на существующем browser
process ownership тесте; он не замалчивается, report и подробности сохранены
в разделе34 [контекста](../docs/clean-vpn-context.md). Повтор не является
доказательством устранения причины того единичного сбоя; process runtime не менялся.

Для pinned route добавлены 28 unit/runtime/preflight регрессий в общий acceptance
и отдельные4 real tests: `npm run test:dns-upstream-route-real`. Последние
используют user/net/mount/PID namespace только с loopback. На него назначаются
IPv4/IPv6 из public-unicast диапазона, поэтому проверяется **настоящая public
policy**, не mocked resolver/loopback exemption. Внешних интерфейсов/маршрутов нет.
Настоящий TCP: первый IP refused, второй выполняет TLS1.3 и DoH; wrong CA не
доставляет DNS body, reset после TCP не вызывает retry, all-down даёт exhaustion
без lookup, restart восстанавливает работу. По5 запросов/10 TCP attempts на
каждый family×modeTag; owned sockets/timers/child processes освобождаются.
Тестирует общий enc-SNI runtime обеих веток; полный clean-vpn с TUN не запускается,
его wiring/preflight дополнительно проверены статически и отдельными unit tests.
Полный acceptance этого пакета: **599 Node-тестов (24 файла) +14 браузерных
сценариев PASS**, report `/var/tmp/meshpn-acceptance-9X9rn3/report.json`.
Отдельно6 прежних real DNS pcap/soak +4 новых route tests: **10/10 PASS**.
