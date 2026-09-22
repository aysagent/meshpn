# Transparent TLS: стенд на одном VPS без TUN

Использует настоящий TLS и те же `attachTransparentTlsClientSession` /
`wireTransparentTlsEncSniSession`, что и clean-vpn. Не запускает `clean-vpn.js`,
не создаёт TUN, не меняет iptables, маршруты, DNS или trust store системы.
Не требует root, native addon, BoringSSL-helper, npm install или внешних сервисов.

Нужен Node.js с TLS/HTTP2 и `node:test` (проверено на Node 24.13.0).
curl нужен только для необязательной ручной проверки.

## Быстрый запуск

Из корня репозитория:

```bash
node scripts/transparent-tls-lab.mjs
# Или:
npm run transparent-tls:lab
```

Команда поднимает стенд на свободных loopback-портах, выполняет проверенные
TLS 1.3 HTTP/1.1 и HTTP/2 запросы с echo 256 КиБ, сравнивает ClientHello/JA3/JA4,
печатает PASS и закрывает слушатели/сокеты. При ошибке exit code ненулевой.

Полный набор интеграционных проверок:

```bash
node --test scripts/test-transparent-tls-integration.mjs
# Или:
npm run test:transparent-tls-integration
```

Отдельные регрессии runtime (лимиты, deadlines, backpressure, cleanup):

```bash
npm run test:transparent-tls-runtime
npm run test:transparent-tls-retry
```

## Ручной curl

```bash
node scripts/transparent-tls-lab.mjs --serve \
  --client-port=18443 --exit-port=19443 --origin-port=20443
```

После автоматической самопроверки процесс печатает `LAB_READY` и готовую команду.
В другом терминале на том же VPS:

```bash
curl --noproxy '*' \
  --connect-to localhost:20443:127.0.0.1:18443 \
  --cacert scripts/fixtures/boring-tls-local.cert.pem \
  https://localhost:20443/
```

Порты можно не задавать: ОС выберет свободные, точная команда будет в выводе.
Разрешены только порт 0 и непривилегированные порты 1024..65535.
Слушатели привязаны к `127.0.0.1`, открыть их на публичном интерфейсе флагом нельзя.
Ctrl+C или SIGTERM завершают стенд. В serve-режиме idle-сокеты закрываются через 30 секунд.

`--connect-to` меняет TCP-адрес только у этой команды curl, но сохраняет SNI,
HTTP Host и имя проверки сертификата из URL. Системного перехвата нет.
Не используйте `-k`: проверка сертификата — часть теста.
`--noproxy '*'` исключает влияние HTTP(S)_PROXY из окружения.

Тестовый сертификат имеет SAN `localhost` / `127.0.0.1`, действует до мая 2036 года.
Его приватный ключ лежит в репозитории: эта пара предназначена ТОЛЬКО для локальных
тестов, не для production. CA передаётся конкретному тестовому клиенту, не устанавливается в ОС.

## Схема

```text
TLS-клиент / curl
  → client listener        capture: исходный ClientHello
  → exit listener          capture: ClientHello с enc-SNI
  → origin TCP tap         capture: восстановленный ClientHello
  → локальный HTTPS origin (ещё один автоматически выделенный loopback-порт)
```

TCP tap только наблюдает и пересылает байты; TLS завершается в HTTPS origin.
Client/exit не получают TLS private/session keys приложения. На запуск создаётся
новый случайный relay PSK. Фабрика подключения origin разрешает только заданное
имя и порт стенда, затем соединяется с фиксированным IPv4 loopback, без DNS.
Даже валидный enc-SNI для другого назначения не превращает стенд в открытый proxy.

Доступны `/` (JSON с TLS/HTTP-параметрами и сведениями о полученном теле) и `/echo`
(ответ исходным телом запроса). Размер тела ограничен 2 МиБ. Полные захваты живут
только в памяти; сохраняются последние 128 записей, не более 64 КиБ на захват.
Диагностика также ограничена. Runtime-логи соединений включены, но origin SNI и
enc-SNI по умолчанию скрыты; подробности раскрывает только `logOpts.ja3Verbose`.

## Что проверяется

- Проверенный сертификат, реальный TLS 1.3, HTTP/1.1 и H2, точная передача 512 КиБ в тестах.
- TLS 1.2 как дополнительный проходящий сценарий.
- Три независимые точки TCP-наблюдения, изменение SNI на участке client→exit.
- Побайтовое равенство **ClientHello handshake body и полного префикса TLS records**
  на входе client и перед origin, включая headers и остаток последнего record.
- Равенство JA3/JA4 на всех трёх точках по существующим анализаторам проекта.
- Параллельные соединения, сопоставленные по ClientHello random.
- Настоящий H1/H2 handshake с ClientHello в двух records, с разрезами заголовка/SNI
  и с однобайтовыми records, поверх множества TCP writes; idle-таймеры обвязки отключены.
- Принудительный TLS 1.3 HRR: origin принимает P-256, клиент сначала предлагает
  X25519 key share. Для H1/H2 захватываются CH1 и CH2 в трёх точках; проверяются
  восстановленные records/JA3/JA4 обоих сообщений и отсутствие plaintext SNI в CH2 на exit.
- Отказ при неправильном PSK, недоверенном CA, неправильном имени сертификата,
  отсутствии SNI, слишком длинном SNI и запрещённом назначении.
- Некорректный/оборванный ClientHello, idle-timeout обвязки, повторный cleanup,
  конфликт порта при запуске и CLI serve/остановка.

Лимиты захвата, idle-timeout и ограничение назначения принадлежат **стенду**.
Отдельный слой защиты теперь есть и в общем runtime — см. следующий раздел.
Без optional `connectOrigin` runtime использует обычный `net.connect(port, hostname)`;
loopback-only ограничение назначения не переносится автоматически на настоящий exit.

## Лимиты общего relay runtime

Client и exit используют [общий I/O lifecycle](lib/transparent-tls-io.mjs), включая
transparent-ветку combo-tls. Значения по умолчанию:

| Параметр `limits` | Значение | Что ограничивает |
| --- | --- | --- |
| `maxHelloBytes` | 64 КиБ | Накопленный первый ClientHello вместе с TLS record headers |
| `maxPendingBytes` | 128 КиБ | Пересобранный ClientHello + уже полученный хвост перед подключением |
| `helloTimeoutMs` | 10 с | Первый ClientHello; отдельно каждая фаза TLS 1.3 SH1/CH2/финального SH, без сброса новыми байтами |
| `connectTimeoutMs` | 10 с | Ожидание исходящего TCP connect, включая асинхронный DNS |
| `writeTimeoutMs` | 30 с | Ожидание drain при backpressure; также завершение после первого EOF |

Заведомо слишком большой TLS record отклоняется по заголовку, не ожидая тела.
Проверка размера накопления выполняется до `Buffer.concat`. Временно накопленные
байты могут занимать до `maxHelloBytes + maxPendingBytes`, плюс копии при разборе
и переписывании SNI. Это **не** общий лимит RSS процесса.

После разбора ClientHello входной сокет приостанавливается на время connect и
записи префикса. Отдельной растущей очереди `pendingToOrigin` больше нет.
В обе стороны `write(false)` останавливает чтение до `drain`; последующие очереди
регулируются high-water mark потоков Node, а не `maxPendingBytes`. Буферы ядра,
один поступивший chunk и суммарное число соединений требуют отдельного учёта.

При ошибке закрывается пара сокетов, снимаются принадлежащие сессии listeners и
таймеры. Error guards остаются до события close. EOF сначала завершает запись
с накопленными данными; зависшее завершение ограничено deadline. Полного idle
timeout для уже установленного молчащего соединения в runtime пока нет.

Переопределения доступны через `opts.limits` функций runtime; CLI-флагов для них
пока нет. Нулевые/некорректные значения и неизвестные параметры запрещены.
Обвязка принимает `clientLimits`, `exitLimits`, `sessionTimeoutMs: 0`: последнее
отключает только её собственные idle-таймеры. Runtime-тесты используют этот режим
и управляемые Duplex для воспроизводимых stalled-connect/drain сценариев.

`onSessionError(error)` получает код `TLS_RELAY_*`; сообщение не содержит
исходный DNS/socket error с доменом, но `error.cause` может его содержать — не
сериализуйте cause в обычные логи. Возвращаемая сессия имеет `closed` (результат:
ошибка либо null); client-функция по-прежнему reject-ится при ошибке подготовки,
exit-функция обрабатывает ошибки внутри себя. Verbose/hex-логи чувствительны.

Внешний exit peek-dispatch в `clean-vpn.js` сохраняет собственные лимиты/таймеры
до передачи соединения relay. Этот пакет не меняет его на глобальную защиту от DoS.

## Обратимое сохранение TLS records

[Rebuild](lib/transparent-tls-ch-rebuild.mjs) больше не склеивает первый ClientHello
в один record и не отбрасывает байты соседнего handshake-сообщения в последнем
record. Полные и частичные последующие records остаются в `tailAfterPrefix`;
runtime передаёт их после восстановленного префикса без перестановки/дублирования.

Алгоритм сохраняет число records и их отдельные legacy versions. При переписывании
меняется SNI и поля длин handshake/расширения; разница длины hostname целиком
приходится на record, содержащий **первый байт SNI hostname**. Все остальные record
lengths неизменны. Это работает и для разрезов внутри SNI: на exit обратное изменение
длины того же record восстанавливает исходный TCP-префикс побайтово. Дополнительных
полей в enc-SNI и новой версии протокола для этого не добавлено.

Ограничения и совместимость:

- На участке client→exit размер одного record меняется: это не обещание идентичного
  wire-профиля на этом участке. TCP packet boundaries и тайминги не сохраняются.
- Если расширение SNI переполняет допустимый record, возвращается
  `record_layout_resize_unsupported`; runtime закрывает соединение **до исходящего
  connect**, с кодом `TLS_RELAY_REBUILD`. Автоматического fallback со склеиванием
  или дополнительной фрагментацией нет. Полный record рядом с пределом может быть
  допустимым исходным TLS, но неподдержанным этим relay.
- Учитывается предел TLSPlaintext 16 КиБ по [RFC 8446 §5.1](https://www.rfc-editor.org/rfc/rfc8446#section-5.1).
  Входной ClientHello record выше предела отклоняется (`record_plaintext_oversize`).
  Сжатие, которое переместило бы начало SNI в другой record, также отклоняется.
- Точная roundtrip-гарантия требует обновления **обоих** endpoint. Старый client
  уже потерял исходное разбиение; старый exit снова склеит records. Формат enc-SNI
  совместим, но старый layout новый endpoint угадать не может.
- Сохранение произвольного соседнего handshake suffix проверено unit/runtime
  тестами как сохранение байтов, не как допустимость любой такой TLS-последовательности.

В основном ClientHello parser устранено повторное `Buffer.concat` после каждого
record: payload склеивается один раз, когда сообщение собрано. Регрессия проверяет
число вызовов concat, а реальные однобайтовые records проходят с прежним deadline.
Это не обещание полной защиты от CPU/connection exhaustion.

## TLS 1.3 HelloRetryRequest / ClientHello2

[Общий HRR guard](lib/transparent-tls-retry.mjs) включается, если CH1 предлагает
TLS 1.3. Он распознаёт специальный ServerHello.random HRR и обрабатывает CCS согласно
[RFC 8446 §4.1.3–4.1.4](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3) и
[§5 / Appendix D.4](https://www.rfc-editor.org/rfc/rfc8446#appendix-D.4).

```text
CH1 → ждать ServerHello
        ├─ обычный ServerHello → raw forwarding
        └─ HRR → собрать/переписать CH2 → ждать финальный ServerHello → raw forwarding
```

- ServerHello и CH2 собираются с лимитами при любых TCP-разрезах и фрагментации
  TLS records. До полного разбора CH2 ни один его байт не отправляется дальше.
- Client повторно подставляет **тот же** enc-SNI. Exit восстанавливает исходное
  имя и использует **то же** открытое соединение с origin — без нового DNS/connect
  и без повторного выбора маршрута. Token из CH1 закреплён за сессией; CH2 не
  декодируется как новый route token с новым сроком действия.
- SNI, legacy version, random и session ID должны совпадать с CH1. Остальные
  изменения CH2 (например, key share/cookie) передаются без подмены. Их полную
  протокольную и криптографическую корректность проверяют TLS endpoints, не relay.
- Dummy CCS `01` перед CH2 и между HRR/ServerHello не выключает guard. CCS не
  допускается внутри фрагментированного hello. Второй HRR или неожиданный CH2
  приводят к закрытию пары сокетов, без raw fallback.
- CH1/CH2 с TLS 1.3 должны заканчиваться на границе record; соседнее plaintext
  handshake-сообщение в том же record отклоняется, чтобы не обойти guard.
  Предыдущее сохранение произвольного suffix в низкоуровневом rebuild остаётся,
  но runtime TLS 1.3 теперь строже. TLS 1.2 raw-ветка этим ограничением не меняется.
- После connect включается абсолютный deadline ожидания ServerHello. Новый deadline
  начинается при HRR (ожидание CH2) и после CH2 (ожидание финального ServerHello).
  Прогресс по байтам/повторные CCS его не продлевают; используется `helloTimeoutMs`.
  Завершение/отмена сессии снимает timers и освобождает накопленные данные.
- CH2 проходит через общий backpressure/drain-timeout. Размеры hello и подготовленной
  записи ограничены теми же `maxHelloBytes`/`maxPendingBytes`; увеличение SNI, которое
  не помещается в record, по-прежнему отклоняется.

Ошибки имеют коды `TLS_RELAY_RETRY_SEQUENCE`, `TLS_RELAY_RETRY_IDENTITY`,
`TLS_RELAY_RETRY_CCS`, `TLS_RELAY_SERVER_HELLO`, `TLS_RELAY_HANDSHAKE_LIMIT`,
`TLS_RELAY_HANDSHAKE_TIMEOUT`, `TLS_RELAY_HANDSHAKE_EOF` (плюс общие ошибки записи/
rebuild). Они не включают hostname/token. Это guard начального handshake, не полный
TLS validator: после обычного финального ServerHello байты снова идут raw.

Стенд теперь хранит `flight: 1 | 2`. `assertRelayTrace(lab, id, flight)` сопоставляет
захваты по ClientHello random **и номеру сообщения**: random у CH2 тот же, поэтому
одного random недостаточно. Реальный TLS проверен на Node; cookie/разрезы HRR/CH2,
нарушения последовательности и медленные peers дополнительно проверяются управляемыми
байтовыми тестами. Это не проверка всех браузеров или всех TLS-стеков.

Для защиты участка client→exit нужен обновлённый **client**. Один обновлённый exit
может отклонить plaintext CH2 старого клиента, но не отменяет уже произошедшую утечку
на проводе. Рекомендуется обновить оба endpoint.

## Границы текущего результата

Это первый integration baseline, не законченный аудит VPN или DPI-устойчивости.

- TLS record layout сохраняется для поддержанных случаев, описанных выше;
  переполнение при увеличении SNI намеренно приводит к отказу.
- Нет обещания сохранить TCP packet boundaries, тайминги или размеры всех пакетов.
- JA3/JA4 вычисляются локальными библиотеками проекта, а не независимым внешним анализатором.
- Автоматический клиент — Node TLS, не Chrome/Firefox. Ручной curl проверяется отдельно;
  браузерный CONNECT-прокси пока не реализован.
- Настоящие ECH, resumption/0-RTT, replay-защита и длительный slow-peer soak пока не
  покрыты. Guard не отключается после раннего application-data record, но это не
  end-to-end проверка 0-RTT. Для HRR покрыт начальный TLS 1.3 handshake; TLS 1.2
  renegotiation и произвольные последующие handshake не добавлены.
- TUN, NAT, LAN, kill-switch, DNS/IPv6-утечки, внешний сетевой путь и реальная производительность
  проверяются следующим отдельным слоем. Дополнительный origin tap тоже влияет на измерения скорости.

Основные файлы: [CLI](transparent-tls-lab.mjs), [обвязка](lib/transparent-tls-lab.mjs),
[интеграционные тесты](test-transparent-tls-integration.mjs).
