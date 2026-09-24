# Transparent TLS: стенд на одном VPS без TUN

Использует настоящий TLS и те же `attachTransparentTlsClientSession` /
`wireTransparentTlsEncSniSession`, что и clean-vpn. Не запускает `clean-vpn.js`,
не создаёт TUN, не меняет iptables, маршруты, DNS или trust store системы.
Не требует root, native addon, BoringSSL-helper, npm install или внешних сервисов.

Нужен Node.js с TLS/HTTP2 и `node:test` (проверено на Node 24.13.0).
curl нужен только для необязательной ручной проверки.
Отдельные 0-RTT тесты требуют Linux, OpenSSL 3.x CLI и `stdbuf` из GNU coreutils;
обычный стенд и Node-наборы этих дополнительных инструментов не требуют.
Для отдельного настоящего ECH-набора нужен Go 1.24+ (проверено с Go 1.26.8).
Он собирает временную fixture только из стандартной библиотеки, без npm/Go-модулей
и без изменения production BoringSSL-helper.
Браузерный набор с независимым pcap имеет отдельные зависимости — см. ниже.

## Единая acceptance-проверка

[Acceptance runner](transparent-acceptance.mjs) запускает фиксированные 30 Node-наборов
и полную матрицу Chrome/Firefox. Он ничего не устанавливает и не скачивает.
Нужны Linux, Node 22+, Go 1.24+, OpenSSL 3, GNU `stdbuf`, `unshare`, `ip` и доступные
user/network/mount/PID namespaces (в том числе для browser-independent lifecycle
регрессий). Для полного режима нужны зависимости браузерного стенда ниже.

```bash
MESHPN_ECH_GO=/path/to/go \
MESHPN_BROWSER_CHROME=/path/to/chrome \
MESHPN_BROWSER_FIREFOX=/path/to/firefox \
MESHPN_CERTUTIL=/path/to/certutil \
MESHPN_TSHARK=/path/to/tshark \
npm run transparent-tls:acceptance -- --repeat=2

# Без браузерных инструментов: только частичная проверка, не full acceptance.
MESHPN_ECH_GO=/path/to/go npm run transparent-tls:acceptance -- --suite=node
```

Go/certutil/tshark/tcpdump можно брать из PATH; пути к обоим браузерам задаются
явно. `MESHPN_TCPDUMP` переопределяет tcpdump, `LD_LIBRARY_PATH` при необходимости
задаётся для извлечённых библиотек. `--repeat=1..3` означает полные последовательные
прогоны, по умолчанию один. Первый сбой прекращает всё: повторов «до зелёного» нет.
Ненулевой exit, deadline, skip/todo, неполная матрица или пропавший инструмент — fail.
Проверяются также дубли сценариев, число TLS-подключений/ClientHello captures и
постоянство версии каждого браузера внутри матрицы.

На preflight-команду отведено 15 с, Node-этап — 180 с, browser-этап — 240 с;
остановка дочерней process group имеет grace 5 с. Вывод ограничен 1 МиБ для
preflight / 4 МиБ для этапа. Собственный deadline browser runner — 180 с.
`SSLKEYLOGFILE`, `NODE_OPTIONS`, `NODE_TEST_CONTEXT` не наследуются; Go запускается
с локальным toolchain и выключенной загрузкой модулей. HOME не подменяется.

Путь к JSON печатается при запуске и завершении. По умолчанию это новый приватный
`meshpn-acceptance-*/report.json` во временном каталоге ОС. Можно указать
`--report=/existing/directory/new-report.json`; существующие файлы и symlinks
не перезаписываются, родительский каталог должен уже существовать. Права файла 0600.
Отчёт сохраняется и при ошибке проверки, не удаляется вместе с browser fixtures.

Schema 1 содержит status, fullAcceptance, Git revision/dirty, фиксированный manifest,
ОС/архитектуру/kernel, Node/embedded OpenSSL, пути и версии внешних инструментов,
длительность/exit/reason каждого этапа, Node counts/имена проваленных тестов и
структурированные результаты браузерных сценариев. У NSS certutil нет надёжного
version-флага: записывается `version: null` и результат проверки `-H`, не выдуманная
версия. Git dirty — только флаг: незакоммиченные исходники и бинарники не архивируются
и не хешируются, поэтому отчёт сам по себе не обеспечивает воспроизводимость сборки.
Raw stdout/stderr, exception stacks, pcap и TLS secrets в JSON не копируются.
Сбор Node-результатов идёт через события [test reporter API](https://nodejs.org/api/test.html#custom-reporters),
а не через нестабильный текст TAP/spec. Уже завершённые этапы сохраняются при сбое
следующего. `--suite=node` может иметь status=passed, но всегда fullAcceptance=false.

SIGINT/SIGTERM запрашивают остановку и отчёт aborted с ненулевым exit.
JSON пишется один раз в конце: SIGKILL/авария ОС/ошибка записи могут оставить пустой
или неполный файл. Ошибка аргументов или резервирования пути возникает до отчёта.
Это не cgroup supervisor; ограничения cleanup процессов описаны ниже.

Текущий полный прогон: **599 Node-тестов + 14 browser-сценариев**. Предыдущий пакет
acceptance был проверен дважды подряд с 235 Node-тестами; basic soak добавил 19,
slow-reader — ещё 11, H2 flow-control — ещё 12, GOAWAY/drain — ещё 12,
browser soak lifecycle/resource contracts — ещё 45 (без запуска браузеров),
enc-SNI replay admission — ещё 34, destination policy — ещё 37, pinned-IP failover — ещё 27.
Explicit-loopback DNS/DoH стенд добавил ещё 46, DNS pcap/soak contracts — 28.
Upstream/bootstrap config contract добавил 65, pinned resolver route — ещё 28.
27 новых регрессий проверяют runner/reporter, включая отсутствие инструмента,
неполные результаты, timeout/abort/output overflow и запрет перезаписи отчёта.
Это ограниченный acceptance, не длительный soak и не production-сертификация.

## Explicit-loopback DNS/DoH

[Отдельный DNS-стенд](transparent-dns-lab.md) принимает явные UDP/TCP queries и
отправляет DoH POST через этот же transparent relay к локальному HTTPS resolver.
Проверяет CA/hostname, malformed responses, timeout/reset/restart, TC/EDNS,
лимиты и отсутствие plaintext fallback. Не меняет DNS системы и не обращается
к публичным resolver. `npm run transparent-tls:dns-lab` — bounded self-check;
`npm run test:transparent-dns` — 46 регрессий, включённых в acceptance.
Наблюдение байтов TLS в этом наборе не заменяет независимый pcap всей сети.
`npm run transparent-tls:dns-soak` отдельно запускает namespace pcap с plaintext
positive control, затем bounded DNS workload и resource checks. Шесть real
регрессий — `npm run test:dns-soak-real`; они не входят в browser acceptance.
[Upstream config](dns-upstream-config.md) задаёт identity/CA/static IP contract;
`npm run dns:check-upstream -- --config=...` только проверяет JSON без сети.
Exit использует bootstrap-IP только с явным `--tls-dns-upstream-config=PATH`
для transparent-tls/combo-tls. Без флага lookup остаётся прежним; клиентский
DNS автоматически не включается. Отдельные4 real namespace проверки IPv4/IPv6
для обеих relay-веток — `npm run test:dns-upstream-route-real`.

## Ограниченный по времени soak

```bash
# Самостоятельный прогон, без Go/браузеров/pcap-инструментов:
npm run transparent-tls:soak
# Пять минут после прогрева, четыре параллельных HTTPS-клиента:
node scripts/transparent-soak.mjs --seconds=300 --concurrency=4
# Короткие регрессии runner (включены в обычный acceptance):
npm run test:transparent-soak
```

[Supervisor](transparent-soak.mjs) держит один worker с одним и тем же
client/exit/origin/CONNECT на протяжении всего прогона. Между волнами стенд не
перезапускается. Нужны Linux `/proc` и Node 22+; проверено на Node 24.13.0.
Нет TUN, перенаправления, изменения DNS/маршрутов, внешнего трафика и установки ПО.
Это Node/OpenSSL-нагрузка, не длительный прогон Chrome/Firefox.

Три полные волны прогрева предшествуют измеряемым `--seconds=1..3600` (default 300).
Каждая волна последовательно выполняет:

- `concurrency` verified TLS 1.3 соединений через CONNECT с HTTP/1.1/HTTP2 echo 64 КиБ;
- столько же FIN-обрывов неполного ClientHello без выхода на origin;
- `floor(concurrency/2)` TLS/H1 upload abort после подтверждённого запроса на origin;
- два drip-fed ClientHello и два drip-fed CONNECT header до реальных deadline;
- здоровый H2 echo после ошибок, чтобы проверить восстановление обслуживания.

`--concurrency=2..12`, default 4, CONNECT admission cap 16. Для законченных hello
каждой волны сверяются полные TLS records, тело ClientHello и JA3/JA4 в трёх точках.
Captures после сверки освобождаются; payload/key material в отчёт не попадает.
Idle-таймеры lab отключены: slow hello ограничивает runtime deadline 300 мс,
slow CONNECT — deadline 300 мс самого proxy. В default `--profile=basic` это медленные
заголовки; для slow-reader после handshake есть отдельный профиль ниже.

После каждой фазы проверяется ноль lab/proxy/workload sockets, H2 sessions,
pending client setup, held responses, header/drip timers и учитываемых relay sessions/timers.
Test-only tracker получает возвращённые runtime session handles и проверяет их
sockets/timers при `closed`, затем удаляет handle из Set. Client setup, завершившийся
ошибкой до возврата handle, учитывается через pendingClients и закрытие сокета:
прямого census его unref timers нет. Production runtime и wire-format не менялись.

Каждая волна требует отсутствия роста FD относительно прогретого worker и нуля
дочерних процессов worker (в этой нагрузке они вообще не создаются). После закрытия
стенда также не должно остаться TCP/Timeout/Process ресурсов, удерживающих event loop.
`getActiveResourcesInfo()` — не полный учёт всех unref/нативных ресурсов;
см. [Node process API](https://nodejs.org/api/process.html#processgetactiveresourcesinfo).
Supervisor требует естественного выхода worker, без `process.exit()` в рабочем коде.
Его `close`/exit/signal попадают в отчёт; остановка использует принадлежащую ему группу
процессов. Это не проверка полного дерева браузера и не cgroup-супервизор.

Волна ограничена 20 с, ожидание освобождения — 5 с, supervisor — seconds+60 с
плюс до 5 с на принудительную остановку. Между волнами пауза 250 мс; последняя волна
может выйти за requested seconds. Runtime stdout/stderr не сохраняются, структурированный
вывод worker ограничен 4 МиБ. На каждую волну проверяется аварийный порог RSS 512 МиБ;
это семплируемая страховка, не жёсткий memory limit ОС и не критерий утечки.

JSON schema 1: версии Node/embedded OpenSSL/ОС, Git revision/dirty, параметры,
результат/счётчики/фаза сбоя, baseline, samples примерно раз в 5 с и final cleanup.
Totals включают прогрев; `waves` — только измеряемые волны, warmupWaves отдельно.
RSS/heapUsed/external/arrayBuffers записываются без forced GC: first/last/peak/delta
и линейный тренд bytesPerMinute. Пики только среди idle-сэмплов, не во время нагрузки.
Рост RSS может отражать allocator/GC; короткая стабилизация не доказывает отсутствие
утечки. В память также входят накопленные samples самого harness.

Путь печатается при старте/окончании, default — приватный `meshpn-soak-*/report.json`
в temp ОС. `--report=/existing/directory/new.json` резервирует новый файл 0600,
существующий файл/symlink не перезаписывается. Отчёт записывается в конце даже при
обычном fail/abort, остаётся после cleanup; SIGKILL/сбой записи могут оставить его
пустым или неполным. Ctrl+C/SIGTERM дают aborted и ненулевой exit. Частичный worker
result никогда не заменяет итоговый status supervisor. Dirty исходники не архивируются.

Реальный прогон на текущем VPS (Linux, Node 24.13.0 / embedded OpenSSL 3.5.4):
300.35 с после прогрева, 294 измеряемых + 3 прогревочных волны, concurrency 4 — PASS.
Всего 2079 TLS-соединений: 1485 echo (92.81 МиБ) и 594 upload abort;
дополнительно 1188 неполных hello abort, 594 slow hello и 594 slow CONNECT.
Idle FD всегда 24, после shutdown 19; учитываемые сокеты/таймеры/сессии нулевые,
worker вышел естественно с code 0. RSS 79.3→106.0 МиБ, heapUsed 12.8→13.0 МиБ;
во второй половине RSS вырос ещё примерно на 1.25 МиБ — строгого «нулевого роста» нет.
Это не доказательство отсутствия memory leak.

Дополнительный прогон 60.40 с, concurrency 12 — PASS: 55+3 волны, 1102 TLS,
754 echo и 348 upload abort; FD снова 24→19. RSS 99.8→130.3 МиБ, sampled peak
133.4 МиБ. Оба прогона проверяют ограниченный интервал, не многочасовую нагрузку.
Финальный acceptance: 254 Node-теста + 14 Chrome/Firefox-сценариев, все pass.

### Slow-reader после handshake: оба направления

```bash
node scripts/transparent-soak.mjs --profile=slow-reader --seconds=300 --concurrency=4
npm run test:transparent-slow-reader
```

Профиль сохраняет basic-волны и добавляет четыре случая: forward/reverse ×
resume/timeout. Сессии используют настоящий verified TLS 1.3 / HTTP/1.1 через
CONNECT → client → exit → origin. HTTP/2 остаётся среди параллельных здоровых
запросов, но **медленный H2 stream/flow-control этим профилем не проверяется**.
Origin/client/exit остаются теми же на всём прогоне.

Opt-in `slowStreams: true` включает только в programmatic lab два endpoint:
`POST /slow-upload` и `GET /slow-download`, ровно по 32 МиБ фиксированного тела.
В обычном lab они не включены. Размер/назначение из запроса не выбираются;
external origin запрещён, максимум два активных stream, страховочный deadline 15 с.
Тела передаются блоками 64 КиБ с ожиданием drain, digest считается потоково —
32 МиБ не собираются в Buffer. Обычный `/echo` по-прежнему ограничен 2 МиБ.

Для forward origin приостанавливает IncomingMessage, для reverse TLS-клиент
приостанавливает чтение ответа после verified handshake. Реальные relay handles
наблюдаются через test-only `relayPressure`: `source.isPaused()` одновременно с
`destination.writableNeedDrain`. Нет такого состояния в пределах бюджета — fail,
а не утверждение, что backpressure проверен. Перед дальнейшими действиями
`concurrency` здоровых H1/H2 echo должны закончиться, пока slow stream ещё блокирован
и runtime ещё не сообщал ошибок. В stdout первые четыре наблюдения помечены `blocked`.

При resume проверяются точный размер 32 МиБ и SHA-256 полученного тела, затем
очистка сокетов/таймеров. При timeout нужен именно `TLS_RELAY_WRITE_TIMEOUT` runtime
(write deadline 2 с); CONNECT deadline 10 с и fixture deadline 15 с не засчитываются.
После подтверждения timeout снимается пауза получателя, чтобы buffered EOF мог
дойти до TLS/HTTP слоя, затем проверяется полный drain. Первый тест обнаружил,
что paused upload reader не видит EOF сразу: relay уже закрыл свои sessions,
но origin fixture оставалась активной. Исправлена последовательность уборки стенда,
а не ослаблены требования к runtime timeout. SIGTERM проверяется во время
реально наблюдаемого forward backpressure, с освобождением paused origin.

Очереди streaming relay семплируются раз в 5 мс: readable/writable не должны
превышать соответствующий highWaterMark + 64 КиБ. Это ограничение наблюдаемых
user-space очередей, не всех kernel/TLS/HTTP/CONNECT/origin-tap буферов и не
доказательство каждого мгновенного пика. Production runtime не изменён.
В JSON `result.slowReaders` содержит по четыре агрегата: cases, доставленные bytes,
pressureSamples, maxReadable/maxWritable и код timeout. Bytes у timeout равен нулю:
частично переданные байты не засчитываются как доставленное тело.
Все счётчики включают три warmup-волны. Одна slow-reader-волна занимает несколько
секунд; `--seconds=1` всё равно проходит полный прогрев и целую измеряемую волну.
Основные пределы supervisor/волны/памяти и ограничения отчёта описаны выше.

Проверено на VPS (Node 24.13.0 / embedded OpenSSL 3.5.4): 300.87 с,
concurrency 4, 47 измеряемых + 3 warmup-волны — PASS. По 50 случаев каждого вида:
100 возобновлённых потоков доставили 3.125 ГиБ с точным SHA-256, ещё 100 получили
runtime write timeout. Всего 1350 TLS-соединений и 1050 здоровых echo.
Наблюдаемые peak relay queues: readable 65 624, writable 65 536 байт.
Idle FD весь прогон 24, после shutdown 19; учитываемые sockets/sessions/timers,
включая slow fixture, нулевые, worker exit 0. RSS 94.3→134.0 МиБ (sampled peak 158.7),
heapUsed 10.1→12.1 МиБ: отсутствие memory leak этим не доказано.

Дополнительно 60.00 с при concurrency 12 — PASS: 9+3 волны, по 12 случаев каждого
вида, 768 МиБ проверенных resume bodies и 732 здоровых echo. FD 24→19,
RSS 101.9→163.9 МиБ. Отдельно проверено корректное отклонение H2-запросов к H1-only
fixture без запрещённого для H2 заголовка `Connection`.

### HTTP/2 flow-control: медленный stream и соседи на одном TLS

```bash
node scripts/transparent-soak.mjs --profile=h2-flow --seconds=300 --concurrency=4
npm run test:transparent-h2-flow
```

Профиль добавляет к basic-волне H2-матрицу forward/reverse × resume/cancel.
**Все четыре случая одной волны используют одну verified TLS 1.3 / H2 session**
через CONNECT/client/exit; следующая волна открывает новую session. Lab/exit/origin
не перезапускаются. Это Node H2, не браузерный H2 soak.

При forward origin приостанавливает чтение request stream, при reverse клиент
приостанавливает response stream. TCP/TLS socket не ставится на pause.
Обязательные наблюдения до и после соседнего трафика:

- `Http2Stream.state.localWindowSize === 0` на получателе;
- `writableNeedDrain === true` на отправляющем stream;
- `Http2Session.state.remoteWindowSize > 0` у отправителя — connection ещё может
  передавать данные других streams.

Смысл полей — [Node HTTP/2 API](https://nodejs.org/api/http2.html#http2streamstate).
Это наблюдения endpoint API, не независимая расшифровка H2 frames из pcap.
Настройки окон не подменяются; тест использует defaults проверенной версии Node.
Отсутствие ожидаемого состояния считается fail.

Во время блокировки `concurrency` соседних echo по 128 КиБ проходят на той же
session. Resume должен доставить ровно 4 МиБ с проверенным SHA-256. Для cancel
дополнительно создаются `concurrency` запросов `/hold`; тест ждёт их поступления
на origin и отправляет `RST_STREAM(CANCEL=8)` только медленному stream.
Origin обязан наблюдать CANCEL, соседние held responses — завершиться с 200,
телом `released` и без reset. После каждого случая проходят новые 128-КиБ echo
на той же session, что проверяет дальнейшую передачу с WINDOW_UPDATE, а не только
возможность открыть пустой stream. Точные значения возвращённого credit/число
WINDOW_UPDATE frames не утверждаются.

Счётчики CONNECT, origin TCP и TLS должны вырасти ровно на один за матрицу.
GOAWAY, session error, runtime error и срабатывание fixture deadline недопустимы;
скрытый reconnect не засчитывается. Между случаями освобождаются все клиентские
streams, slow fixture и held responses, сама session остаётся живой. После матрицы
проверяется обычный полный drain и побайтовое восстановление ClientHello/records/JA3/JA4.

Programmatic `h2Flow: true` включает `/h2-flow-upload` и `/h2-flow-download` только
на внутреннем origin. Это H2-only endpoints, фиксированное тело 4 МиБ, блоки 16 КиБ,
максимум два slow streams и deadline 15 с. Deadline закрывает **stream**, не session,
но в успешном тесте вообще не должен срабатывать. H1/неверные параметры отвергаются,
в default lab endpoints отключены. Production runtime/wire-format не менялись.

В `result.h2Flow` отчёта: число TLS-соединений матриц, здоровые echo (отдельно от
basic `totals`) и четыре агрегата cases/bytes/zeroWindowSamples/healthyWhileBlocked/
healthyAfter/heldSurvived/rstCode. Счётчики включают warmup. Очереди H2 stream
семплируются раз в 5 мс, fixture budget 256 КиБ на readable/writable очередь;
это не общий предел TLS/kernel buffers и не доказательство каждого мгновенного пика.
Действуют прежние deadlines, лимит RSS, защита отчёта и ограничения cleanup.
Отдельная регрессия прерывает runner SIGTERM после наблюдения исчерпанного окна.

Первый длинный H2-прогон остановился на 57-й волне (включая три warmup) с assertion,
по счётчикам — в начале reverse-resume; ресурсы после cleanup освободились. Исходный отчёт не
сохранял конкретное поле assertion. Обнаружен дефект ожидания: оно проверяло только
stream window и needDrain, после чего отдельная assertion требовала положительный
connection window. Эти значения на двух endpoints обновляются асинхронно.
Теперь bounded wait ждёт все три условия, а assertion проверяет тот же снимок,
не повторный потенциально изменившийся. Две детерминированные регрессии проверяют
позднее появление connection credit и запрет повторного чтения при валидации.
При ошибке отчёт сохраняет case/step/снимок окон и числовые actual/expected,
без payload или stack. Неуспешный прогон не засчитан как pass.

Финальный VPS-прогон после исправления: 303.33 с, concurrency 4, 98 измеряемых
+ 3 warmup-волны — PASS. 101 H2-матрица/соединение, по 101 случаю каждого вида:
202 resume доставили 808 МиБ с точным SHA-256; 202 CANCEL не повредили 808 уже
ожидавших соседних responses. 3333 H2 echo прошли на тех же sessions, отдельно
от basic-трафика. Все counters включают warmup. Sampled очереди: readable до
131 070, writable до 65 536 байт. Idle FD постоянно 24, после shutdown 19;
учитываемые sockets/streams/timers нулевые, fixture deadlines 0, worker exit 0.
RSS 88.3→160.0 МиБ (peak 162.3), heapUsed 8.9→11.1 МиБ — отсутствие утечек не заявляется.

После исправления также прошёл прогон 61.71 с / concurrency 12: 13+3 волны,
16 H2-матриц, 128 МиБ resume, 32 CANCEL, 384 held survivors, 1552 H2 echo,
FD 24→19. Полный acceptance: 277 Node-тестов + 14 Chrome/Firefox-сценариев, все pass.

### HTTP/2 GOAWAY: drain с активными streams

```bash
node scripts/transparent-soak.mjs --profile=h2-goaway --seconds=300 --concurrency=4
node scripts/transparent-soak.mjs --profile=h2-goaway --seconds=60 --concurrency=12
npm run test:transparent-h2-goaway
```

К basic-волне добавляются два случая: GOAWAY во время upload и download.
У каждого случая одна verified TLS 1.3 / H2 session через CONNECT/client/exit.
Все слушатели живут весь прогон; новые TLS sessions создаёт только явный следующий
случай/волна. Это тест origin-initiated graceful drain, не остановка VPN-сервиса.

Порядок проверки:

1. Передача 4 МиБ блокируется на уровне stream. Как в `h2-flow`, проверяется
   нулевое принимающее окно, backpressure отправителя и положительное connection
   window. TCP/TLS socket не ставится на pause.
2. На той же session создаются `concurrency` POST `/hold`. Все должны реально
   поступить на origin до начала drain. Тест знает последний принятый stream ID.
3. Lab вызывает `Http2Session.close()`. Клиент обязан получить GOAWAY с `NO_ERROR`;
   границы не возрастают, покрывают все принятые streams, последняя граница точно
   соответствует последнему принятому ID. Разрешено до восьми GOAWAY events.
4. Новый POST на закрывающейся session обязан синхронно получить
   `ERR_HTTP2_GOAWAY_SESSION`. Никакого fallback/reconnect/retry в workload нет.
   После этого 100 мс сохраняются заблокированный stream и ожидающие responses;
   ни клиентская session, ни origin drain ещё не должны завершиться.
5. Origin освобождает held responses, получатель возобновляет slow stream.
   Проверяются 200, полный END_STREAM без ошибок/reset, точные 4 МиБ/SHA-256 и
   все соседние responses. Затем обе стороны должны закрыть session естественно.
   `destroy()` в `finally` — страховка cleanup, а не способ пройти этот критерий.
6. До и после drain origin request count увеличивается ровно на `concurrency+1`,
   TLS/origin TCP/CONNECT counters — ровно на один. Это обнаруживает дубликаты и
   скрытое переподключение в тестируемом пути. После случая проверяются idle ресурсы
   и полный trace ClientHello/JA3/JA4 на client/exit/origin.

Семантика graceful close — [Node HTTP/2 API](https://nodejs.org/api/http2.html#http2sessionclosecallback),
границы GOAWAY и запрет новых streams — [RFC 9113 §6.8](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8).
Тест намеренно не создаёт admission race: все streams приняты **до** GOAWAY.
Он не проверяет REFUSED_STREAM для запросов, пересёкшихся с GOAWAY в сети,
ошибочные GOAWAY, браузерные retry policies или exactly-once доставку в общем случае.
Наблюдения получены через endpoint API, не через расшифровку H2 frames из pcap.

Существующий lab-only `drainOriginHttp2()` по-прежнему имеет deadline 5 с;
его таймер теперь явно очищается и учитывается в `h2DrainTimers`/`assertIdle`.
Deadline не засчитывается как successful close. Fixture deadline 15 с и reset
медленного stream также недопустимы в успешном случае. Общие лимиты soak, bounded
cleanup и ограничения измерения памяти остаются прежними. Production relay,
wire-format, TUN/mesh и BoringSSL не изменялись.

JSON `h2Goaway.forward/reverse`: `cases`, `bytes`, `heldSurvived`, `refused`,
`tlsConnections`, `naturalCloses`, `goaways`; счётчики включают три warmup-волны,
basic totals записаны отдельно. При ошибке сохраняются direction/step, числовой
снимок окон, ограниченный список GOAWAY code/lastStreamID и состояние закрытия;
opaque debug data, payload, TLS secrets и exception stacks не сохраняются.
Добавлены проверки границ/ошибочных свидетельств, короткий настоящий soak и
SIGTERM во время drain в обоих направлениях с проверкой очистки таймеров/сокетов.

Пятиминутный VPS-прогон concurrency 4: 301.64 с после warmup, 106+3 волны — PASS.
218 graceful closes, 872 МиБ с точным SHA-256, 872 held POST responses завершены,
218 новых запросов явно отклонены. FD во всех idle samples 24, после shutdown 19;
отслеживаемые sockets/streams/timers нулевые, fixture CANCEL/deadline 0,
worker естественно завершился с exit 0. RSS 86.9→141.0 МиБ, peak 142.9;
heapUsed 9.1→19.2 МиБ, external 3.8→51.9 МиБ, arrayBuffers 0.3→48.3 МиБ.
Это sampled trend без принудительного GC, не доказательство отсутствия утечек.

VPS-прогон concurrency 12: 61.41 с после warmup, 21+3 волны — PASS.
48 graceful closes, 192 МиБ с точным SHA-256, 576 held POST responses завершены,
48 новых запросов явно отклонены, скрытых повторов/переподключений нет.
FD 24 между волнами → 19 после shutdown; учитываемые ресурсы нулевые,
fixture CANCEL/deadline 0, worker exit 0. RSS 103.3→115.9 МиБ, sampled peak 120.6.
Полный acceptance прошёл дважды: 289 Node-тестов + 14 Chrome/Firefox-сценариев,
второй раз — после усиления проверки cleanup при истечении drain deadline.

### Bounded soak с настоящими Chrome/Firefox

```bash
# Используются уже настроенные MESHPN_BROWSER_CHROME / MESHPN_BROWSER_FIREFOX,
# MESHPN_CERTUTIL и, если бинарникам нужны локальные shared libraries, LD_LIBRARY_PATH.
node scripts/transparent-browser-soak.mjs --seconds=300 --concurrency=4
node scripts/transparent-browser-soak.mjs --browser=firefox --seconds=60 --concurrency=12
npm run test:browser-soak
npm run test:browser-soak-real
```

По умолчанию Chrome и Firefox выполняются **последовательно по 300 измеряемых
секунд каждый**, после трёх warmup-волн. Диапазоны: 1..3600 секунд на браузер,
concurrency 2..12; `--browser=chrome|firefox|all`. Никаких скачиваний, установки
библиотек или отключения browser sandbox/TLS verification. Missing browser — fail,
не skip. Нельзя указать внешний target или использовать личный профиль.

Каждый browser worker держит один реальный browser process/profile, одну страницу
и постоянные lab/client/exit/origin/CONNECT listeners весь прогон. Временная CA
доверена только приватному профилю; тот же генератор CA/leaf теперь используется
коротким browser acceptance. TLS 1.3, HTTP/2, ClientHello и HTTP/User-Agent создаёт
сам браузер, без BoringSSL-профилей или динамического клонирования.

Волна:

1. `concurrency` параллельных POST echo по 64 КиБ: точное сравнение тела в браузере.
2. `concurrency` POST `/hold` должны реально поступить на origin; половина
   отменяется `AbortController`, origin обязан освободить соответствующие responses.
3. Оставшиеся ответы освобождаются и должны завершиться с 200/`released`.
   Отменённые fetch должны вернуть именно `AbortError`.
4. Диагностический запрос проверяет TLS 1.3/H2 и native UA. Маркер страницы и
   localStorage остаётся тем же; браузер не перезапускается. Счётчик origin requests
   требует ровно `2*concurrency+1`, без скрытых повторов workload-запросов.
5. После завершённых запросов origin делает GOAWAY/drain. Все lab/CONNECT ресурсы
   должны стать idle; следующая волна открывает ровно одну новую TLS session.
   Счётчики origin TCP/TLS/CONNECT и один ClientHello в каждой из трёх точек
   исключают скрытые переподключения. `assertRelayTrace` проверяет восстановленные
   байты ClientHello, record layout, JA3/JA4, затем bounded captures очищаются.

Это не browser GOAWAY с активными запросами: активный drain покрывает отдельный
Node `h2-goaway`. Здесь браузер переоткрывает session **после** завершения волны.
TLS resumption возможен и учитывается origin, но не требуется на каждом reconnect:
браузер управляет потреблением tickets. Ни TLS secrets, ни ticket bytes не пишутся.
Браузерные фоновые попытки доступа вне фиксированного lab origin отклоняются
CONNECT gate и видны в его rejected counter; они не считаются workload retries.

У каждого worker отдельные user/network/mount/**PID** namespaces; `/proc` отражает
только его процессы, сеть содержит только `lo`. Worker — PID 1; Chrome NSS mount
остаётся приватным. `unshare --kill-child=SIGKILL` связывает жизнь namespace init
с launcher; завершение init убирает также потомков с отдельной process group.
См. [unshare](https://man7.org/linux/man-pages/man1/unshare.1.html) и
[PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).
Две регрессии проверяют это для TERM-resistant detached descendant при SIGTERM
и SIGKILL владельца namespace. Это не cgroup и не гарантия cleanup файлов при
SIGKILL внешнего supervisor/аварии ОС.

Ресурсы семплируются в idle после каждой волны, JSON time series — раз в ≥5 с:

- дерево worker+browser: ≤64 живых процессов, ≤64 zombies, ≤4096 FD,
  сумма RSS ≤3 ГиБ; worker отдельно ≤512 МиБ RSS;
- после warmup: worker FD не растут; дерево допускает до baseline+8 процессов,
  baseline+8 zombies, baseline+128 FD из-за ленивого запуска browser subprocesses;
- сумма RSS **повторно считает общие страницы**, не равна уникально занятой RAM.
  Нет принудительного GC, PSS/cgroup измерений или мгновенного OS-enforced лимита;
- после close требуется полный читаемый снимок с единственным живым worker,
  нулевыми lab/CONNECT counters и отсутствием TCP/server/timer/process handles.
  Zombies считаются отдельно, не выдаются за живые процессы; они исчезают вместе
  с PID namespace. Истёкший/недоступный cleanup snapshot — fail.

Во время завершения sandboxed Firefox чтение `/proc/<pid>/fd` может временно
вернуть EACCES. После stop используется bounded wait до 5 с за полным снимком;
EACCES/EPERM не заменяются нулями. Постоянная недоступность, живой остаточный
процесс и неожиданные ошибки проверяются отрицательными unit tests. Чтение
ресурсов во время обычной нагрузки остаётся fail-closed без таких повторов.

Wave deadline 30 с, команды CDP/BiDi ≤15 с, supervisor deadline `seconds+90` на
браузер с kill grace 5 с. Вывод worker ограничен 4 МиБ, отчёт создаётся `wx/0600`
и не перезаписывается. Приватные profile/NSS/CA/key файлы удаляются родителем;
JSON содержит версии браузеров, revision+dirty, counters и числовые ресурсы,
не raw stderr/RPC/stack, URL назначения, payload или TLS secrets. Независимого
pcap/tshark внутри долгого soak нет: он остаётся отдельной acceptance-проверкой.

`test:browser-soak` — 45 browser-independent проверок bounds/evidence/resource
accounting/namespace ownership. `test:browser-soak-real` — четыре отдельные
проверки Chrome/Firefox: короткий soak с concurrency 12 и SIGTERM во время held
requests. Этот opt-in набор требует настоящих браузеров и не входит в Node-only
acceptance. Длительность в несколько минут не доказывает отсутствие утечек,
DPI-неотличимость или production-ready состояние.

Финальные VPS-прогоны с исправленным cleanup (Node 24.13.0):

| Браузер | Измеряемое время | Волны + warmup | Echo по 64 КиБ | Отменено / завершено held | TLS sessions / traces ClientHello |
|---|---:|---:|---:|---:|---:|
| Chrome 151.0.7922.10 | 300.20 с | 592 + 3 | 2380 | 1190 / 1190 | 596 / 1788 |
| Firefox 156.0.1 | 300.51 с | 574 + 3 | 2308 | 1154 / 1154 | 578 / 1734 |

Оба PASS, ровно один browser launch на прогон. Counters включают warmup и одну
начальную navigation session. Суммарно 293 МиБ echo с точным сравнением байтов.
Worker FD стабильно 27 → 19 после cleanup. Sampled tree FD: Chrome 611→582
(521..612), Firefox 465→500 (465..510). Live tree: 15..17 и 12..13 процессов.
Summed tree RSS: Chrome 1648.5→1586.7 МиБ (peak 1699.4), Firefox 1030.5→1157.7
(peak 1165.6); worker RSS 76.4→91.8 и 75.2→93.8 МиБ соответственно.
Показатели не доказывают отсутствие утечек.

После cleanup у обоих только живой worker/PipeWrap; отслеживаемые relay/CONNECT
сокеты/таймеры нулевые. Chrome оставляет 7 zombies, Firefox 11 внутри PID namespace
до выхода init; оба worker завершаются естественно с exit 0, namespace закрывается,
приватные profile/NSS/CA/key файлы удалены. Firefox cleanup потребовал один повтор
чтения после временного EACCES и получил полный снимок; ошибка не скрыта нулями.

Дополнительно на финальном коде PASS по минуте с concurrency 12, оба браузера
последовательно: Chrome 60.38 с / 94+3 волны / 1164 echo / 582 abort / 98 TLS;
Firefox 60.56 с / 86+3 / 1068 echo / 534 abort / 90 TLS. Полный acceptance:
334 Node-теста + 14 browser-сценариев, отдельно четыре real-soak регрессии — PASS.

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
npm run test:transparent-tls-resumption
```

Настоящий 0-RTT с OpenSSL endpoints (отдельно от Node HTTPS-тестов):

```bash
npm run test:transparent-tls-early-data
```

Отсутствующие OpenSSL/`stdbuf` или несовместимый CLI приводят к ошибке теста,
не к молчаливому skip. Проверено на Linux: Node 24.13.0, OpenSSL 3.0.13.

Настоящий ECH с Go TLS endpoints:

```bash
npm run test:transparent-tls-ech
# Если go не в PATH:
MESHPN_ECH_GO=/path/to/go npm run test:transparent-tls-ech
```

Go toolchain тестом не скачивается. Сборка использует `GOTOOLCHAIN=local`,
`GOPROXY=off`, `GOSUMDB=off`, `GOWORK=off`, выключенный cgo и приватный временный
build cache. Отсутствие подходящего Go или ошибка сборки — fail, не skip.

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
новый случайный relay PSK. Destination policy разрешает только заданное имя и
порт стенда, затем connector получает фиксированный IPv4 loopback, без DNS.
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

## Destination policy exit и DNS rebinding

[Policy](lib/transparent-tls-destination.mjs) включена по умолчанию в общий
`wireTransparentTlsEncSniSession`: transparent exit, transparent-ветку combo и
standalone exit listener. Это **проверка внутри приложения**, не firewall.
Mesh, TUN, NAT, iptables/nftables, системный DNS и работающие VPN-процессы не меняются.
Wire format v2 и TLS bytes после восстановления исходного SNI не меняются.

Порядок допуска: authentication/rebuild → replay reservation → проверка имени и
порта → одно разрешение DNS → проверка **всех** полученных IP → TCP к одному
числовому IP → проверка remoteAddress/remotePort → отправка ClientHello.
Denied/DNS-failed route тоже расходует token: повтор не должен повторять DNS.
Combo classifier остаётся stateless; policy failure после relay dispatch не
переключает соединение на mux. CH2/HRR использует уже открытый проверенный origin.

Default разрешает консервативное подмножество public-unicast IPv4/IPv6:

- IPv4: запрещены `0/8`, RFC1918, `100.64/10`, `127/8`, `169.254/16`,
  `192.0.0/24`, `192.0.2/24`, `192.88.99/24`, `198.18/15`, `198.51.100/24`,
  `203.0.113/24`, multicast/reserved `224/3`.
- IPv6: только `2000::/3`, за исключением `2001::/23`, `2001:db8::/32`,
  `2002::/16`, `3fff::/20`. ULA, link-local, multicast, mapped/compatible IPv4,
  известные NAT64 prefixes, Teredo/6to4, scoped addresses не проходят.
- Это намеренно более строгая политика, чем точная копия флага IANA Globally
  Reachable: некоторые специальные globally-reachable exceptions тоже закрыты.
  Основание диапазонов: [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/)
  и [IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/).
- Порт должен быть целым `1..65535`; нового ограничения «только 443» нет.
  DNS labels — ASCII/IDNA LDH, без пустых/слишком длинных labels, trailing dot,
  single-label names, legacy numeric IPv4 и локальных suffixes
  `.localhost`, `.local`, `.internal`, `.home.arpa`. IP literal v4 проверяется
  без DNS; literal IPv6 по-прежнему не представлен в enc-SNI v2 hostname.

OS `dns.lookup` получает абсолютное имя с завершающей точкой и
`{all:true, verbatim:true}`. Проверяются все A/AAAA-адреса из результата системного
resolver; смешанный public/private ответ отвергается целиком, а не фильтруется.
Не более 64 ответов. Все проверенные адреса копируются в immutable список
targets, эквивалентные IP дедуплицируются с сохранением порядка OS resolver.
`net.connect` получает IP, family и `autoSelectFamily:false`, не hostname:
повторного lookup и окна check-by-name/connect-by-name нет. Новый admission делает
новый lookup и заново проверяет результат. DNS authenticity этим не обеспечивается.

Перебор происходит **только до выбора TCP-соединения**, последовательно:
`ECONNREFUSED`, `ECONNRESET`, `ETIMEDOUT`, `ENETUNREACH`, `EHOSTUNREACH`,
`ENETDOWN`, `EHOSTDOWN`, `EADDRNOTAVAIL` до connect дают перейти к следующему
проверенному адресу. Незавершённая попытка, если за ней есть ещё адреса, получает
250 мс; затем её socket.destroy() вызывается до запуска следующей. Последний
кандидат получает остаток общего connect deadline, не новый полный таймаут.
Не более 64 кандидатов, один ещё не отменённый TCP connect за раз. Дубликаты не
создают дополнительные попытки. Это bounded sequential fallback, не параллельный
Happy Eyeballs: порядок семейств не меняется и RTT не обучается.

`RelaySession.connectCandidate` удерживает закрываемые сокеты в owned set до
`close`, поглощает их отложенные ошибки и снимает попыточные таймеры/listeners.
После TCP connect обычный fail-closed lifecycle восстанавливается сразу.
Peer mismatch, локальные configuration/resource/permission ошибки, ошибка TLS,
write/reset после выбора соединения **не** запускают новый IP. ClientHello и его
coalesced tail отправляются только выбранному socket, один раз. Один token и
одна replay reservation охватывают весь перебор; нового DNS при retry нет.

Один deadline `connectTimeoutMs` (default 10 с) охватывает DNS **и** TCP.
Close/timeout прекращает ожидание; поздний DNS success/rejection не открывает
сокет и не оставляет необработанный reject. В default singleton не более 64
незавершённых DNS lookup, без очереди. OS getaddrinfo нельзя надёжно отменить:
после timeout его слот удерживается до фактического settlement, чтобы поток новых
соединений не создал неограниченную очередь libuv. Постоянно зависшие OS lookup
могут исчерпать бюджет; это fail-closed, не автоматический обход проверки.
Семантика системного lookup описана в [Node DNS](https://nodejs.org/docs/latest-v24.x/api/dns.html#implementation-considerations).

Programmatic test hook `connectOrigin(address, port, family)` теперь получает
**числовой адрес**, а не исходный hostname. Policy проверяется и при custom
connector; перед отправкой prelude его фактический peer обязан совпасть с target.
В harness используется `new ExitDestinationPolicy({loopback:{hostname,port}})`:
разрешено только точное имя и порт собственного origin, адрес всегда `127.0.0.1`.
Это не общий `allowPrivate`, не DNS bypass для произвольного назначения и не CLI
флаг. Явные `destinationPolicy:null/false/{}` отклоняются как configuration error.

| Код | Причина |
| --- | --- |
| `TLS_RELAY_DESTINATION` | Имя/порт/IP или смешанный DNS ответ запрещён |
| `TLS_RELAY_DESTINATION_PEER` | Connector подключился не к проверенному адресу/порту |
| `TLS_RELAY_DNS` | Ошибка, пустой/неправильный/слишком большой DNS ответ |
| `TLS_RELAY_DNS_BUSY` | Все 64 resolver slots заняты |
| `TLS_RELAY_CONNECT_TIMEOUT` | Истёк общий бюджет DNS+TCP |
| `TLS_RELAY_CONNECT_EXHAUSTED` | Все кандидаты закончились retryable TCP-ошибкой |

`TLS_RELAY_CONNECT_ATTEMPT_TIMEOUT` — внутренний переход после 250 мс, не
ошибка всей session. Если общий deadline наступил раньше — приоритет у него.

В обычный лог попадает код, не DNS answer или raw resolver exception.
`ja3Verbose` остаётся явно sensitive режимом. Нет CLI отключения policy.

Проверка: `npm run test:transparent-tls-destination` — 64 теста. DNS rebinding,
mixed A/AAAA, IPv4 encodings/IPv6 prefixes, connector pin/peer mismatch, malformed
routes, bounded DNS, abort/late success/late failure, deadline DNS+TCP проверяются
детерминированными doubles без внешних DNS/TCP запросов. Реальный TCP negative
test отправляет валидный token на loopback origin через default exit и требует
**ноль** origin connections. Положительный настоящий TLS H1/H2/HRR/browser путь
проверяется общим lab с узким loopback pin. Полный acceptance на VPS:
**432 Node-теста (20 файлов) + 14 Chrome/Firefox-сценариев** — PASS.
Отдельные четыре real-browser soak/SIGTERM регрессии — PASS.

27 новых failover-проверок покрывают sync/async отказ, 250 мс blackhole,
late connect/error, дедупликацию IPv6, immutable snapshot, исчерпание всех 64
кандидатов, отказ при последнем forbidden IP, отмену второй попытки, запрет
повторной отправки ClientHello после reset, общий DNS+TCP deadline и peer mismatch.
Два настоящих TLS 1.3 H2 echo (64 КиБ), baseline и forced HRR, сначала получают
ECONNREFUSED на первом loopback IP, затем завершаются на втором с проверенным CA.
Для этих двух тестов список loopback кандидатов задан **только test double**
policy; production public-unicast policy не ослабляется.

Ограничения и совместимость:

- Ранее доступные private/split-DNS origin теперь будут отвергаться — это
  намеренное изменение admission. Mixed DNS также fail-closed.
- Sequential fallback не обещает проверить все 64 IP за 10 с: общий deadline
  приоритетнее полноты перебора. 250 мс может быть недостаточно для медленного,
  но работающего не-последнего IP. Параллельный Happy Eyeballs/адаптация RTT не добавлены.
- Не выявляются публичные IP собственных интерфейсов, нестандартные NAT64 prefixes,
  DNAT/маршрутизация публичного IP во внутреннюю сеть и публичные provider service
  addresses вне запрещённых диапазонов. Это не полная SSRF-изоляция окружения.
- Нет domain allowlist, per-client quotas, DNSSEC/DoH, запрета всех не-HTTPS
  public ports, общего ECH routing или защиты остальных transport/mux веток.
- DNS клиента не перенастроен и его возможная LAN/IPv6 утечка не устранена.
  Политика exit не делает клиентский DNS конфиденциальным.

## Replay-защита enc-SNI route token

`wireTransparentTlsEncSniSession()` теперь по умолчанию использует общий
process-local [EncSniReplayGuard](lib/transparent-tls-replay.mjs). Это изменение
production relay runtime, не только lab. Через ту же функцию защищены
transparent-ветки standalone и combo-tls в `clean-vpn.js`, а также no-TUN exit
helper. TUN/mux dispatch и client wire-format не менялись.

Admission происходит после успешных AES-GCM decode, проверки timestamp,
восстановления ClientHello и ограничений prelude, но **до** `connectOrigin()`/
DNS/TCP connect. Синхронная запись в cache предшествует любому await подключения:
из двух конкурирующих предъявлений одного token допускается только одно.
Запись не освобождается при закрытии сокета, ошибке подключения или неуспешном
TLS handshake. Повторный захваченный token не создаёт новый origin socket.

Идентификатор — SHA-256 аутентифицированных бинарных `nonce || ciphertext || tag`,
а не текст SNI. Переразбиение encrypted prefix на DNS labels, пустые labels,
допускаемые текущим parser, или регистр public suffix не обходят cache.
Регистр самого base62 ciphertext по-прежнему значим. Изменение ClientHello
random/параметров не даёт повторно использовать уже потреблённый token.
Decoder возвращает дополнительные `issuedAtSeconds` и `replayId`; эти поля
нельзя писать в обычные логи. Неаутентифицированные/просроченные token не занимают
cache. В нём хранятся только digest и deadline, не hostname/PSK/raw token.

Default budget — **65 536 записей**, фиксированное удержание **601 000 мс** с
момента допуска. Причина: timestamp допускает ±300 секунд, включая целую
граничную секунду; впервые предъявленный на нижней границе token может ещё
приниматься примерно 600 секунд. Простых пяти минут хранения недостаточно.
Guard повторно проверяет timestamp непосредственно при reservation.

Cache сохраняет insertion order, лениво удаляет истёкшие записи при новом
валидном admission (амортизированное O(1), без per-token таймеров). При заполнении
**не вытесняет ещё удерживаемые записи**: новое соединение отклоняется. Размер
ограничен числом записей, а не точно измеренным RSS/V8 heap. На полностью занятом
cache возможен отказ легитимным клиентам; 65 536 / 601 ≈109 новых token/с —
ориентир длительной нагрузки без запаса на bursts, не гарантированная пропускная
способность или rate limit. Это общий бюджет всех PSK/listeners в процессе,
не per-user fairness и не полноценная DoS-защита.

Clock high-water mark не допускает новые соединения при откате `Date.now()`
до возвращения часов к последнему наблюдённому значению. Иначе шаг вперёд,
очистка cache и последующий откат могли бы снова сделать старый token валидным.
Невалидные часы/переполнение тоже дают отказ. Это сознательный fail-closed
операционный tradeoff: коррекция системных часов назад может временно прервать
новые relay admissions, но не уже установленные сессии.

| Код | Причина отказа до origin connect |
|---|---|
| `TLS_RELAY_REPLAY` | Token уже использован |
| `TLS_RELAY_REPLAY_FULL` | Cache заполнен, живые записи не вытесняются |
| `TLS_RELAY_REPLAY_CLOCK` | Часы невалидны или откатились |
| `TLS_RELAY_REPLAY_STALE` | Timestamp вышел из окна между decode и admission |
| `TLS_RELAY_CONFIG` | Некорректный явно переданный guard/его параметры |

Обычный HRR не является новым admission: CH2 обрабатывает существующий
`createHelloRetryGuard` на том же соединении, с прежним relay SNI/random/session
identity. Повторной записи в cache нет; CH2 работает и при cache capacity=1.
CH2 с другим token отклоняет identity guard; копия CH2 на новом TCP-соединении
отклоняется replay guard. `classifyComboTlsExitPrefix()` остаётся stateless:
peek не расходует token, а уже использованный валидный token всё ещё классифицируется
как relay, после чего отвергается runtime, без downgrade в TLS/TUN mux.

Programmatic `opts.replayGuard` принимает только `EncSniReplayGuard`, `null/false`
не выключают защиту. Уменьшенный `maxEntries` доступен через конструктор (1..65536),
CLI disable/resize/clear не добавлены. Production callers используют singleton;
нельзя создавать новый guard на каждый accept. Lab создаёт отдельный guard на
весь свой lifetime и публикует только числовой `stats().replay`. Ненулевые entries
после закрытия сессий — намеренная security state, не незакрытые handles.

Границы гарантии:

- Это at-most-one admission в пределах **одного guard/process lifetime**, не
  распределённый/durable cache. Другой worker/host или restart имеют новую память;
  всё ещё свежий захваченный token там может пройти. Cluster/shared state не добавлены.
- Не защищает от гонки первого предъявления: перехватчик, успевший первым,
  может занять token и сорвать легитимное подключение. К ClientHello transcript
  token криптографически не привязан; последующая end-to-end TLS аутентификация
  остаётся ответственностью приложения/origin.
- Не заменяет TLS 0-RTT anti-replay origin, exactly-once HTTP, destination policy,
  global socket quotas, защиту raw TUN или аудит внешнего peek-dispatch.
- Wire format v2, AES-GCM/key derivation, ±5-минутное окно, JA3/JA4 и клиентский
  ClientHello не изменены. Существующий client уже создаёт новый nonce на каждое
  подключение; повторно использовать ранее сохранённый token нельзя.

`npm run test:transparent-tls-replay`: 34 проверки, включая реальный TLS/HRR,
перехваченные CH1/CH2 и DNS aliases, отсутствие лишнего origin connect, cache
capacity=1/65536, inclusive future timestamp, expiry/rollback, ошибки connector,
повреждённую аутентификацию, process-default scope и отсутствие secrets в логах.
Криптографические/часовые границы тестируются с управляемыми часами, без ожидания
10 минут; это не заявление о durable защите после reboot.

Проверено на VPS: полный acceptance **368 Node + 14 browser** — PASS, включая
HRR/resumption/ECH/0-RTT; четыре отдельные real-browser soak/SIGTERM регрессии
тоже PASS. С включённым cache прошли concurrency 12 / 60.11 с Chrome и 60.47 с
Firefox: 99/90 TLS sessions, 1176/1068 echo, 588/534 отмены. Final replay entries
99/90 совпадают с admissions, несмотря на закрытые сокеты; worker exit 0,
живых браузерных процессов после cleanup нет, FD 19, private profiles удалены.
Это проверка совместимости под ограниченной нагрузкой, не production-сертификация.

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

## TLS session resumption без 0-RTT

[Отдельный набор](test-transparent-tls-resumption.mjs) проверяет настоящие новые
TCP/TLS-соединения, а не повторные запросы внутри существующей HTTP/2-сессии.
Изменений production relay для этих сценариев не потребовалось: расширены стенд
и проверки, TLS-сессия по-прежнему принадлежит приложению и origin.

На Node 24.13.0 проходят 12 новых тестов:

- TLS 1.2 и TLS 1.3 ticket resumption для HTTP/1.1 и HTTP/2; повторное использование
  подтверждается `isSessionReused()` на клиенте и origin, не только HTTP-ответом.
- Отказ от старого ticket после ротации ключей origin: полный handshake, выдача
  нового session state и успешное возобновление с ним. Это управляемая проверка
  отказа, не ожидание естественного истечения срока ticket.
- TLS 1.3 resumption вместе с настоящим HRR для обоих HTTP-протоколов: клиент
  пересчитывает binder CH2, relay сохраняет его, origin принимает сессию.
  CH2 использует прежний enc-SNI и уже открытое соединение с origin.
- При полном handshake после отказа от ticket неверные CA/hostname по-прежнему
  отклоняются до отправки HTTP. Это не обещание новой проверки сертификата при
  принятом resumption: там используется ранее установленное доверие к сессии.
- Четыре параллельные независимые сессии, передача echo, сопоставление captures
  с конкретным клиентским соединением и закрытие всех сокетов.
- Session state выдаётся только по явному запросу, ограничен 64 КиБ и не попадает
  в JSON результата.

В TLS 1.3 проверяются реальные байты `pre_shared_key` (extension 41): identities
и binders неизменны во всех трёх точках, PSK остаётся последним extension,
`early_data` (42) отсутствует. Для каждого CH1/CH2 отдельно сравниваются исходный
и восстановленный ClientHello, records и JA3/JA4. Cold и resumed ClientHello могут
иметь разные отпечатки: добавление PSK — нормальное изменение, их равенство между
разными соединениями не является критерием приёмки.

Пример программного использования внутри уже запущенного стенда:

```js
const first = await requestThroughLab(lab, { captureSession: true });
assert.ok(Buffer.isBuffer(first.session));
const second = await requestThroughLab(lab, {
  tlsOptions: { session: first.session },
});
assert.equal(second.sessionReused, true);
assert.equal(JSON.parse(second.body).sessionReused, true);
```

Состояние берётся из первого события TLS `session`, обработчик ставится до
`secureConnect`: в TLS 1.3 ticket может прийти после handshake. Отсутствие ticket
не маскируется под успешное resumption. См. [Node 24.13.0: session event](https://nodejs.org/download/release/v24.13.0/docs/api/tls.html#event-session).
`requestThroughLab` не ждёт ticket бесконечно: он возвращает результат после
HTTP-ответа; если события не было, `session` останется `undefined`.

`first.session` содержит чувствительное состояние TLS-клиента, не только публично
наблюдаемый ticket. Оно хранится в памяти теста, не записывается в профиль или лог;
свойство non-enumerable исключает случайное включение в `JSON.stringify` результата,
но не является защитой от явного чтения/логирования. Вызывающий код должен ограничивать
повторное использование тем же origin и настройками доверия. Общего session cache
в relay или механизма переноса tickets между браузерными профилями здесь нет.

Только для тестов стенд предоставляет `rotateTicketKeys()` и
`setOriginGroups(ecdhCurve)`: первый инвалидирует прежние tickets, второй меняет
группы origin с сохранением текущих ticket keys, позволяя вызвать HRR при resumption.
Ключи не возвращаются наружу. Эти методы не являются production API транспорта.

Всего вместе с integration/runtime/retry/enc-SNI/JA4 — 120 тестов. Матрица ограничена
Node/OpenSSL; 0-RTT, естественное истечение tickets и все браузерные TLS-стеки ею
не проверены.

## Настоящий 0-RTT и пересечение ранних данных с HRR

[OpenSSL-набор](test-transparent-tls-early-data.mjs) запускает `s_client` и
`s_server` как настоящие TLS endpoints. Между ними — прежние client/exit relay
и origin tap, только IPv4 loopback. TLS проверяет CA и hostname `localhost`;
relay не получает TLS session keys и не завершает TLS.

Проверяются четыре end-to-end сценария:

- Принятие 0-RTT при resumption и точное получение payload один раз через
  early-data API origin. Клиент также подтверждает `Reused` и принятие early data.
- Повтор той же сохранённой сессии отклоняется origin с включённым `-anti_replay`:
  полный handshake успешен, ранний payload не доставляется повторно. Эти две
  проверки повторяются с `-max_send_frag 512` для множества малых TLS records.
- HRR отвергает early data, но завершается обычный handshake. До явного действия
  приложения payload не появляется у origin; после явной отправки в 1-RTT приходит
  ровно один раз. Relay ничего не переотправляет самостоятельно.
- То же с управляемой задержкой настоящих encrypted records до прохождения HRR
  через оба guard. Порядок байтов внутри каждого TCP-направления не меняется.
  Проверка не полагается на случайный timing loopback.

Для CH1 подтверждается настоящий `early_data` extension 42 и последний PSK
extension 41. В CH2 extension 42 уже отсутствует; SNI/records/JA3/JA4
восстанавливаются, enc-SNI остаётся прежним. После handshake проверяется обмен
прикладными данными в обе стороны и закрытие соединений. Это тестовые TLS payloads,
**не** HTTP/1.1 или HTTP/2 early requests и не браузерная проверка.

Именно задержанный сценарий воспроизвёл runtime-ошибку: guard принимал ранние
records только до получения HRR и отклонял ещё летящие к origin байты после него.
Теперь records типа 23 пропускаются также в ожидании CH2, пока не началось
собирание его handshake. После начала фрагментированного CH2 вставка early records
запрещена; после полного CH2 до финального ServerHello она тоже запрещена.
Ни размерные ограничения, ни абсолютный deadline не ослаблены; ранние records
не продлевают ожидание. Исправление нужно на client **и** exit.

Семантика отказа/повторной отправки и пересекающихся потоков описана в
[RFC 8446 §4.2.10](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.10).
Принятие или отбрасывание ранних данных остаётся задачей TLS origin. Проверка
повторного ticket здесь использует одноразовый cache OpenSSL, см.
[OpenSSL 3.0: replay protection](https://docs.openssl.org/3.0/man3/SSL_read_early_data/#replay-protection).
Это не новая replay-защита enc-SNI, не проверка повторного воспроизведения целого
захваченного TCP-потока и не гарантия exactly-once между разными origin/processes.

Программный параметр `externalOriginPort` переключает backend стенда на уже
запущенный TLS origin, только `127.0.0.1` и непривилегированный порт. CLI-флага нет;
destination pinning exit не меняется. В этом режиме Node-origin не слушает порт,
его ticket/group controls отклоняются, а `tlsConnections`, `resumedTlsConnections`
и `requests` возвращаются как `null`: внешний origin нужно наблюдать отдельно.
Passive capture теперь пропускает до 64 КиБ opaque records, чтобы увидеть CH2
после early data; это лимит наблюдения, не лимит production early data.

В отличие от memory-only Node resumption, OpenSSL CLI использует временный файл
session state: каталог создаётся с правами 0700, файлы с 0600, cleanup завершает
процессы и удаляет каталог. Stdout/stderr OpenSSL могут содержать секреты: они
ограничены 512 КиБ суммарно на процесс, не сохраняются и не включаются в ошибки
теста. `stdbuf` устраняет перемешивание буферизованных диагностических заголовков
`s_server` с его непосредственной записью payload. Принудительное завершение
самого test runner через SIGKILL не гарантирует cleanup временного каталога.

Итого 5 новых OpenSSL/lab-тестов и 3 guard-регрессии, весь набор — **128 тестов**.
Не покрыты максимальные объёмы early data, все варианты server rejection,
распределённый replay, HTTP-семантика ранних запросов и браузерные TLS-стеки.

## Настоящий ECH: криптография и границы маршрутизации

[ECH-набор](test-transparent-tls-ech.mjs) использует отдельную
[Go fixture](fixtures/transparent-ech/main.go) с настоящим `crypto/tls`, а не
синтетическое расширение GREASE. Сертификаты, CA, ECH private keys и конфигурации
создаются на запуск и остаются в памяти процесса. TLS завершается только в
тестовых endpoints; Node relay этих ключей не получает.

В тесте inner SNI — `hidden.ech.test`, outer SNI — `public.ech.test`, а участок
client→exit несёт enc-SNI с суффиксом `relay.test`. Exit восстанавливает outer SNI;
origin tap направляет его в фиксированный loopback ECH endpoint. Только там
расшифровывается inner hello и проверяется скрытое имя. Эти тестовые имена не
разрешаются через публичный DNS.

Принятие ECH подтверждается `ECHAccepted` **на клиенте и сервере**, проверкой
сертификата и точным SHA-256/размером принятого HTTP payload. Совпадение байтов
расширения или одного JA3 само по себе подтверждением не считается.

Девять Go end-to-end проверок покрывают:

- HTTP/1.1 и HTTP/2 с принятым ECH, затем отдельное TCP-соединение с настоящим
  resumption, подтверждённым обоими endpoints.
- HRR для обоих HTTP-протоколов; каждый исходный handshake record CH1/CH2 разбит
  на однобайтовые records. ECH payload не меняется на relay, CH2 содержит новый
  ciphertext и пустой `enc`; сохраняются прежний route token и один origin connect.
- Устаревший ECHConfig: отказ без HTTP, затем **явный** новый запрос клиента
  с аутентифицированными retry configs и успешным ECH.
- Origin без ECH, неверный сертификат inner имени, неверный сертификат outer
  имени при отказе от ECH и недоверенный CA. Нет HTTP и автоматического
  переподключения с отключённым ECH в проверяемом клиенте.

CH1/CH2 сравниваются во всех трёх точках; восстановленный hello и TLS records
идентичны исходным. В plaintext captures скрытого имени нет. Здесь JA3/JA4 —
отпечатки **outer** ClientHello, не скрытого inner и не всего сетевого профиля.
Дополнительно две быстрые runtime-регрессии проверяют отказ client/exit до
исходящего connect, если есть opaque ECH extension, но отсутствует outer SNI;
это структурные отрицательные тесты, не успешные ECH handshakes.

Политика текущего relay (без нового wire-format или флага):

- ECH/GREASE ECH остаётся opaque: расширение не удаляется и не подменяется,
  наличие `0xfe0d` не используется как признак принятого/настоящего ECH.
- Маршрут выбирается по **outer SNI + порту**. Inner имя не угадывается;
  отсутствие outer SNI закрывает соединение с `TLS_RELAY_HELLO`, без raw fallback.
- HRR использует прежний маршрут и сохраняет существующие проверки outer
  SNI/random/session ID. Варианты второго outer hello, которые этим условиям не
  соответствуют, отклоняются guard; поддержка всех разрешённых ECH-вариантов и
  TLS-стеков не заявляется.
- При отказе TLS endpoint relay передаёт alert/закрытие; сам не отключает ECH,
  не меняет сертификатную проверку, не переподключается по inner имени и не
  применяет retry configs. Решение о retry принимает приложение.

Почему возможно восстановление ECH: outer hello участвует в аутентифицируемых
данных HPKE, поэтому недостаточно сохранить только ciphertext. До ECH endpoint
нужно восстановить весь исходный outer hello. См.
[RFC 9849 §5.2](https://www.rfc-editor.org/rfc/rfc9849.html#section-5.2).
При отклонении ECH сертификат public name не подтверждает inner origin: такой
handshake не должен отдаваться приложению как успешное подключение к inner.
В стенде это проверяет Go TLS, см.
[RFC 9849 §6.1.6–6.1.7](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.6)
и [Go TLS Config](https://pkg.go.dev/crypto/tls#Config).

**Ограничение production routing остаётся:** enc-SNI v2 хранит hostname и порт,
но не исходный destination IP. DNS outer public name на exit не обязан указывать
на тот же ECH endpoint, который приложение выбрало по HTTPS/SVCB/DNS. Успешный
loopback-тест с pinning это не решает. Пакет не вводит автоматический обход ECH,
передачу исходного IP или новый протокол маршрута; для общего решения потребуется
отдельный дизайн с destination policy/SSRF-защитой, IPv4/IPv6 и DNS-семантикой.

Саму обработку ECH менять не потребовалось, но многократные прогоны обнаружили
отдельную runtime-ошибку TCP half-close: стандартный `net.Socket` с
`allowHalfOpen=false` после FIN закрывал и обратное направление, теряя поздние
байты. Три регрессии с настоящими TCP-сокетами проверяют FIN сначала от client,
FIN сначала от origin и зависшую после FIN сторону. `RelaySession` теперь включает
`allowHalfOpen` у обоих принадлежащих ему сокетов, передаёт каждый EOF независимо
и сохраняет прежний абсолютный close deadline (`writeTimeoutMs`). Origin tap и
фрагментирующий proxy стенда тоже сохраняют half-close. Обновить нужно client и
exit; wire-format не меняется.

Go-клиент при закрытии ограниченно дочитывает TCP после TLS close_notify, чтобы
непрочитанные завершающие records не создавали тестовый RST после уже проверенного HTTP-ответа.
Вывод fixture — только ограниченные JSON-результаты (до 64 КиБ на процесс), без
секретов/сырого TLS debug; дочерние процессы и временные binary/cache удаляются
cleanup. После SIGKILL самого runner cleanup не гарантирован.

Весь набор: **142 теста** (прежние 128, 9 настоящих ECH и 5 runtime-проверок).
Проверено на Linux, Node 24.13.0, Go 1.26.8. Не покрыты ECH+0-RTT, DNS HTTPS/SVCB,
публичные CDN/ECH endpoints, все HPKE suites, браузеры и независимый pcap-анализ.

## CONNECT, настоящие Chrome/Firefox и независимый pcap

Ручной CONNECT-стенд, без браузерных зависимостей:

```bash
node scripts/transparent-tls-lab.mjs --serve --connect-port=0
npm run test:transparent-connect
```

После self-check `LAB_READY` содержит `connectPort`; CLI печатает готовую команду
curl с `--proxy`, `--noproxy ''` и `--cacert`. CONNECT направляется **только** на
`localhost:<originPort>` этого стенда, а TCP — на фиксированный client relay.
Произвольные hostname/IP/порты, обычный HTTP и неоднозначный framing отклоняются.
Это не общий SOCKS/HTTP proxy и не production ingress. Лимиты по умолчанию:
32 соединения, 8 КиБ / 32 заголовка, 3 с на заголовки/connect/blocked write/half-close,
30 с idle. TLS заканчивается только в браузере и HTTPS origin, не на CONNECT proxy.
19 Node-тестов проверяют H1/H2, сертификаты, framing/allowlist, fragmented headers,
coalesced tunnel bytes, лимиты, отказ upstream и освобождение ресурсов.

Полная браузерная проверка:

```bash
MESHPN_BROWSER_CHROME=/absolute/path/to/chrome \
MESHPN_BROWSER_FIREFOX=/absolute/path/to/firefox \
npm run test:transparent-browser
# Или один браузер:
MESHPN_BROWSER_CHROME=/absolute/path/to/chrome npm run test:transparent-browser -- chrome
```

Нужны Linux, Node 22+ с встроенным WebSocket, разрешённые unprivileged user/network/mount
namespaces, `unshare`, `mount`, `ip`, `openssl` 3.x, NSS `certutil`, `tcpdump`,
`tshark` с полями `tls.handshake.ja3` и `tls.handshake.ja4` (4.2+) и зависимости
указанных браузеров. Допустимы `MESHPN_CERTUTIL`, `MESHPN_TCPDUMP`, `MESHPN_TSHARK`.
Runner ничего не скачивает и не устанавливает. Отсутствие инструментов/прав/полей
анализатора — ошибка, не skip и не fallback с отключением защиты.

Для каждого браузера создаётся свежий профиль на каждый сценарий: без доверия
к тестовому CA либо с доверием только во временной NSS DB. OpenSSL создаёт эфемерные CA и отдельный
leaf для `localhost`, действующие один день. Старый self-signed fixture с CA:TRUE
не используется: Firefox отвергает его как end entity. Сертификатные проверки
и браузерная sandbox не отключаются; нет `--ignore-certificate-errors`,
`--no-sandbox` или `acceptInsecureCerts: true`. HOME не переопределяется.

У Chrome существующая legacy `~/.pki/nssdb` имеет приоритет: временная DB
монтируется поверх неё **только в дочернем mount namespace**, без записи в
реальное хранилище пользователя. Если legacy отсутствует, используется временный
XDG_DATA_HOME (современный Chromium, M146+). Firefox использует собственный
временный профиль и `security.enterprise_roots.enabled=false`.
См. [Chrome certificate management](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md).
CONNECT для localhost включён только в тестовом процессе браузера;
см. [Chromium proxy bypass rules](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md).

Весь runner работает в **новом network namespace**, в котором только `lo`.
Нет доступа к внешней сети или localhost-сервисам хоста; поднимается только его
собственный loopback. tcpdump снимает настоящие пакеты только на трёх портах lab:
client, exit, origin. Это не синтетический pcap, собранный из собственного parser.
Tshark независимо собирает TCP/TLS и проверяет SNI/JA3/JA4 по TCP stream,
стороне/peer port, ClientHello random и номеру flight в каждой точке.
Полный восстановленный ClientHello и TLS record bytes отдельно
проверяет `assertRelayTrace`. Поля — [Wireshark TLS reference](https://www.wireshark.org/docs/dfref/t/tls.html).

Успешный сценарий проверяет TLS 1.3, HTTP/2, точное echo 88 КиБ и совпадение
наблюдаемого origin User-Agent с `navigator.userAgent`. UA, TLS extensions,
HTTP/2 SETTINGS и порядок заголовков не подменяются — их формирует сам браузер.
Отрицательный сценарий требует конкретной certificate error, нуля HTTP-запросов
и подтверждения реального CONNECT/ClientHello в pcap. `localhost /browser`
отдаёт минимальную страницу без внешних ресурсов; `/` — диагностический JSON.

Управление Chrome идёт через CDP, Firefox через WebDriver BiDi, без npm automation
зависимостей. Есть deadlines команд/всего runner (180 с), ограниченный вывод
процессов и предел 10 000 пакетов на capture. Каталоги приватные (0700), umask
0077; TLS secrets/keylogs не пишутся (`SSLKEYLOGFILE` не наследуется). Профили,
ключи, pcap и дочерние процессы убираются после теста/ошибки/SIGTERM. После
SIGKILL runner или аварии ОС cleanup не гарантирован. Pcap не коммитится.

Проверено: Linux, Node 24.13.0, OpenSSL 3.0.13, tshark 4.2.2,
Chrome for Testing 151.0.7922.10, Firefox 156.0.1.
**599 Node-тестов + 14 браузерных сценариев**, без ошибок и пропусков.
Первоначальный baseline (161 + 4) расширен HRR и resumption, описанными ниже.
Browser ECH/0-RTT, HTTP/3, GUI-браузеры, длительный профиль нагрузки и внешний
сетевой путь ещё не покрыты.
Нативный ClientHello и его JA3/JA4 не означают неотличимость всего TCP-потока от
прямого браузерного соединения: relay меняет соединения, сегментацию и тайминги.

### Браузерные HRR, resumption и отклонение ticket

Без дополнительных CLI-флагов runner выполняет по семь сценариев на браузер:

| Сценарий | Обязательное доказательство |
| --- | --- |
| `untrusted` | Certificate error, ноль HTTP, реальный CONNECT/ClientHello |
| `baseline` | Полный verified TLS 1.3 + HTTP/2 + echo |
| `hrr` | На каждом участке CH1 → HRR → CH2 → SH, один origin connect |
| `resumption` | Новый TCP/TLS, PSK offer и selection, origin `sessionReused=true` |
| `resumption-hrr` | Новый resumed TLS с HRR; PSK в обоих CH, binder/records восстановлены |
| `ticket-rejection` | PSK действительно предложен, не выбран сервером; полный verified handshake |
| `parallel-abort` | Отмена четырёх из восьми достигших origin H2-запросов не ломает соседние streams/TLS |

HRR вызывается ограничением групп **только на origin**: P-256 для проверенного
Chrome и P-384 для Firefox. Firefox 156 уже присылает P-256 key share в CH1,
поэтому P-256 не вызывал HRR — тест это обнаружил, а не зачёл как PASS.
ClientHello/список групп браузера не подменяется. Если будущая версия браузера
станет сразу предлагать нужный share, сценарий завершится ошибкой и потребует
пересмотра origin fixture. CH2 сохраняет random и прежний enc-SNI token;
побайтовое восстановление проверяется отдельно для каждого flight.

Для нового соединения programmatic lab-only `drainOriginHttp2()` отправляет
GOAWAY через `Http2Session.close()` и ждёт закрытия с deadline 5 с. Процесс браузера
и его TLS-кеш остаются прежними; listeners, CA и ticket keys не меняются.
См. [Node HTTP/2 session close](https://nodejs.org/api/http2.html#http2sessionclosecallback).
Контроль вызывается между завершёнными запросами, не через доступный по HTTP endpoint.
Две Node-регрессии проверяют новое возобновлённое соединение после GOAWAY и
ограниченное ожидание незавершённого запроса. Смена групп при resumption+HRR
сохраняет ticket keys, а `ticket-rejection` явно их ротирует до повторного connect.

Принятие и отказ ticket проверяются в отдельных свежих профилях: в реальном
прогоне Firefox после успешного resume не предложил PSK на третьем соединении.
Отсутствие PSK нельзя выдавать за server rejection. Поэтому `ticket-rejection`
требует PSK в CH первого повторного соединения, его отсутствия в финальном SH,
`sessionReused=false`, нового origin connect и успешного verified HTTP/2 echo.
Сами tickets не извлекаются из браузера, не инжектируются и не логируются.

[Pcap matcher](lib/browser-lab-pcap.mjs) сопоставляет каждый пассивный capture
ровно с одним `tcp.stream`/peer/random/flight; проверяет полноту обеих сторон,
порядок CH/HRR/SH и extension 41 (`pre_shared_key`) в CH и финальном SH.
HRR распознаётся по специальному ServerHello random. Отпечатки CH1 и CH2 не
обязаны совпадать между собой: каждый flight сравнивается с **собственным**
оригиналом во всех трёх точках. Количество CONNECT/origin соединений тоже
проверяется, чтобы скрытый reconnect не подменил проверку HRR/resumption.

```bash
npm run test:browser-pcap
```

30 быстрых регрессий matcher используют **синтетические строки tshark**, отдельно
от настоящего сетевого захвата в браузерной матрице. Покрыты потеря CH2/HRR/SH,
ошибки отпечатков/SNI, ложный PSK/resume, перемешанные потоки, повторное
использование peer port, дубли, лишние/отсутствующие captures и ошибочные поля.
Неоднозначные несколько hello в одной строке fields, неожиданные потоки или
неполный capture дают fail, не частичный PASS. Это ограниченный analyser стенда,
не универсальный парсер произвольных pcap/ретрансляций.

Ограничения: browser ticket renewal после resume, 0-RTT и certificate-error
именно при rejected-ticket fallback ещё не проверены этой браузерной матрицей
(отрицательный CA baseline и соответствующие Node-тесты существуют отдельно).
Короткий параллельный прогон и отмены HTTP/2 streams добавлены ниже; множество
независимых браузерных процессов и browser slow-reader здесь не покрыты.
Отдельный bounded browser soak с ресурсными счётчиками описан выше.

## Ограниченная нагрузка, медленные стороны и отмена запросов

```bash
npm run test:transparent-load
# Проверка владения группами процессов (Linux /proc, без браузеров):
npm run test:browser-process
# Браузерная матрица включает parallel-abort автоматически:
npm run test:transparent-browser
```

[Нагрузочные тесты](test-transparent-tls-load.mjs) используют только фиксированный
loopback lab/CONNECT и настоящие сокеты. Параметры намеренно ограничены в коде,
нет аргумента для произвольного внешнего target или бесконечной нагрузки.
В Node-части idle-таймеры harness выключены, чтобы они не скрывали ошибки runtime.

- Шесть волн по 12 независимых verified TLS-соединений, поровну H1/H2,
  всего 72 handshake и echo 18 МиБ. Каждая волна сравнивает ClientHello/JA3/JA4
  во всех трёх точках, затем требует нуля lab sockets, proxy clients/upstreams
  и header timers до начала следующей. Capture ring очищается только после сверки.
- 72 обрыва во время неполного ClientHello с успешным контрольным запросом после
  каждой волны; 24 обрыва незавершённого H1 upload уже после TLS handshake,
  одновременно с успешным независимым echo.
- По шесть медленных ClientHello и CONNECT headers. Периодические байты не
  продлевают абсолютный deadline 250 мс: первый случай подтверждается кодами
  `TLS_RELAY_HELLO_TIMEOUT` до origin connect, второй — ответами 408 и
  освобождением admission slots. Большой proxy idle timeout не может зачесть PASS.
- Четыре отдельных **raw TCP pump**, не TLS, теста: forward/reverse ×
  возобновление чтения/таймаут. Оба конца настоящие TCP sockets; reader приостановлен,
  producer пишет с backpressure и бюджетом не более 32 МиБ на тест. Обязательно
  наблюдаются `writableNeedDrain` и пауза relay reader; если ядро вместило весь
  бюджет и backpressure не возник — fail, не пропуск проверки.
  При resume проверяется точная доставка 32 МиБ; при stall —
  `TLS_RELAY_WRITE_TIMEOUT`. После завершения нет relay sockets/timers/data/drain
  listeners. Проверяются измеряемые очереди не выше соответствующего high-water
  mark + 64 КиБ chunk. Это не доказательство глобального memory bound.

На проверенном Linux/Node 24.13.0 измеряемые пики readable/writable очередей
relay были 64/64 КиБ. Они семплируются каждые 5 мс и в точке обнаружения паузы,
поэтому не являются исчерпывающим трассированием каждого краткого пика. RSS
печатается как диагностика, **не** как критерий отсутствия утечек: V8 и ядро
кешируют память, а данный набор не выполняет длительный heap/kernel анализ.
Не проверены production-глобальные квоты на все соединения и память процесса.

В настоящих Chrome/Firefox `parallel-abort` выполняет четыре волны: восемь
одновременно удерживаемых `/hold` запросов, ожидание их появления на origin,
отмена первых четырёх через AbortController, успешное завершение остальных.
После каждой волны — восемь параллельных echo по 64 КиБ с разными данными.
Сохраняется ровно одно TLS/CONNECT-соединение: это **H2 multiplexing**, а не
восемь независимых TCP-соединений. TLS/HTTP2/UA и pcap-проверка ClientHello
сохраняются; RST/HTTP2-cancellation подтверждаются endpoints, без TLS keylog.

Test-only gate включается только programmatic `holdResponses: true` у внутреннего
lab origin. По умолчанию `/hold` — обычный ответ lab, в CLI отдельного флага нет.
Gate ограничен 16 ответами (17-й получает 503), имеет свой deadline 5 с (504),
идемпотентный release и cleanup при abort/close. Три Node-регрессии проверяют эти
границы; браузер ждёт наблюдаемых held counters, а не отменяет запрос до его отправки.

Тест владения процессами воспроизвёл дефект старой обвязки: после завершения
родителя таймер SIGKILL отменялся, а descendant, игнорирующий SIGTERM, мог остаться.
Теперь при `exit` лидера добивается **принадлежащая ему detached process group**;
это также закрывает унаследованные stdio pipes, не позволяя зависнуть на `close`.
Различие событий — [Node child_process](https://nodejs.org/api/child_process.html#event-close).
Три Linux-регрессии проверяют обычную/idempotent остановку и устойчивого потомка
с отдельным либо унаследованным stdio. Zombie считается остановленным: reaping
сироты делает PID 1. Потомки, намеренно ушедшие в новую session/process group,
SIGKILL runner и авария ОС не покрыты; это не замена cgroup-супервизору.

Итого добавлены 12 Node load/gate тестов, 3 process-теста и 2 browser-сценария.
Проверено **208 Node-тестов + 14 browser-сценариев**; браузерная матрица повторена.
Это короткая ограниченная проверка стабильности, не benchmark, не суточный soak
и не доказательство production/DPI-безопасности. Единый повторяемый acceptance
runner и отдельный ограниченный по времени soak с наблюдением ресурсов
уже добавлены (см. начало документа).

## Границы текущего результата

Это первый integration baseline, не законченный аудит VPN или DPI-устойчивости.

- TLS record layout сохраняется для поддержанных случаев, описанных выше;
  переполнение при увеличении SNI намеренно приводит к отказу.
- Нет обещания сохранить TCP packet boundaries, тайминги или размеры всех пакетов.
- Основные наборы используют Node/OpenSSL/Go; отдельный браузерный набор проверяет
  реальные Chrome/Firefox через CONNECT и независимо сверяет JA3/JA4 с tshark.
- Добавлена ограниченная process-local replay-защита route token (см. выше);
  public-unicast destination policy и numeric IP pinning действуют на transparent
  ветке exit, но не заменяют DNS privacy клиента или firewall (см. выше);
  durable/distributed replay-защита и общий ECH routing не добавлены. Есть bounded Node soak
  с обрывами, медленными заголовками, H1 slow-reader, H2 stream flow-control и
  GOAWAY при активных streams; отдельный bounded browser soak описан выше.
  Суточный browser soak, browser slow-reader и внешний сетевой путь не проверены.
  Настоящий ECH проверен в Go-матрице с pinned loopback origin, 0-RTT —
  отдельно в OpenSSL-матрице, без проверки их сочетания. Для HRR покрыт начальный
  TLS 1.3 handshake; TLS 1.2
  renegotiation и произвольные последующие handshake не добавлены.
- TUN, NAT, LAN, kill-switch, DNS/IPv6-утечки, внешний сетевой путь и реальная производительность
  проверяются следующим отдельным слоем. Дополнительный origin tap тоже влияет на измерения скорости.

Основные файлы: [CLI](transparent-tls-lab.mjs), [обвязка](lib/transparent-tls-lab.mjs),
[интеграционные тесты](test-transparent-tls-integration.mjs),
[resumption-тесты](test-transparent-tls-resumption.mjs),
[0-RTT тесты](test-transparent-tls-early-data.mjs), [ECH-тесты](test-transparent-tls-ech.mjs).
