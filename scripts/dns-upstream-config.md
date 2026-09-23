# DNS upstream/bootstrap: offline configuration contract

Это **конфигурационный контракт и его проверка на loopback-стенде**, не включение
production DNS. Не выбирает публичный resolver, не отправляет внешние запросы,
не меняет OS DNS, TUN, firewall, mesh или работающий VPN.

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
  Число не включает runtime доступ к этому порту: будущая route policy
  должна отдельно разрешить назначение. Только DoH POST поверх TLS1.3+.
- `path`: простой абсолютный путь ≤256 символов, например `/operator/dns`.
  Без URL, query string, `%` escapes, fragment, dot segments, пустых segments,
  auth/token, URI template. Такие DoH deployments пока не поддерживаются.
- `bootstrap.addresses`: 1..8 явно заданных числовых public-unicast IPv4/IPv6.
  Весь список проходит существующую консервативную exit IP policy; один private/
  loopback/special-use адрес отвергает **всю** конфигурацию. Duplicate/equivalent
  IPv6 удаляются с сохранением порядка. Никакого DNS lookup для bootstrap.
  Список становится immutable snapshot с address/family/port; он **пока не
  подключён к connector** и не означает реализованный failover resolver.
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

## Что ещё не сделано

Рабочий exit всё ещё разрешает destination hostname через свой OS resolver.
Загрузка этого JSON **не** меняет это поведение. Следующий отдельный пакет —
узкая операторская pinned route на exit для конкретного resolver hostname+port:
подключаться к проверенному snapshot IP без lookup и без расширения общей
destination policy. Проверить это на стенде, прежде чем включать где-либо.
Нельзя просто передать первый IP в прямой HTTPS connect клиента: это обойдёт
согласованный relay-путь.

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
