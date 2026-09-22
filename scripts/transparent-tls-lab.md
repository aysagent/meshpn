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
- Побайтовое равенство **ClientHello handshake body** на входе client и перед origin.
- Равенство JA3/JA4 на всех трёх точках по существующим анализаторам проекта.
- Параллельные соединения, сопоставленные по ClientHello random.
- Настоящий handshake с ClientHello в двух TLS records и множестве TCP writes.
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
| `helloTimeoutMs` | 10 с | Абсолютное ожидание первого ClientHello, не сбрасывается новыми байтами |
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

## Границы текущего результата

Это первый integration baseline, не законченный аудит VPN или DPI-устойчивости.

- Восстановление handshake body не означает сохранения исходной TLS record fragmentation:
  текущий runtime собирает ClientHello в один record; тест явно фиксирует это поведение.
- Нет обещания сохранить TCP packet boundaries, тайминги или размеры всех пакетов.
- JA3/JA4 вычисляются локальными библиотеками проекта, а не независимым внешним анализатором.
- Автоматический клиент — Node TLS, не Chrome/Firefox. Ручной curl проверяется отдельно;
  браузерный CONNECT-прокси пока не реализован.
- HRR/ClientHello2, настоящие ECH, resumption/0-RTT, replay-защита и длительный slow-peer soak
  пока не покрыты. Нельзя считать их исправленными на основании PASS этого стенда.
- TUN, NAT, LAN, kill-switch, DNS/IPv6-утечки, внешний сетевой путь и реальная производительность
  проверяются следующим отдельным слоем. Дополнительный origin tap тоже влияет на измерения скорости.

Основные файлы: [CLI](transparent-tls-lab.mjs), [обвязка](lib/transparent-tls-lab.mjs),
[интеграционные тесты](test-transparent-tls-integration.mjs).
