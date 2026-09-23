# Защищённый DNS: explicit-loopback стенд

Это **стенд**, а не включение DNS-защиты в системе. Ничего не меняет в
`resolv.conf`, systemd-resolved, браузерах, firewall, маршрутах, TUN или mesh.
Работающий VPN не перезапускает. Внешние DNS/TCP-сервисы не используются,
пакеты не отправляются на порт 53. Нужен только Node (проверено 24.13.0).

```bash
npm run transparent-tls:dns-lab
npm run test:transparent-dns
```

CLI автоматически поднимает стенд на случайных loopback-портах, проверяет 8
запросов и закрывает все ресурсы. Прямого serve/deploy режима пока нет;
неизвестные аргументы отвергаются. Deadline CLI 15 с; SIGINT/SIGTERM запускают
cleanup и дают ненулевой результат. Успех — единственная строка
`DNS_LAB_RESULT {...}` после проверки cleanup, без реальных QNAME/ответов/ключей.
Это stdout-отчёт, не сохраняемый автоматически JSON-файл или pcap.

## Путь запроса

```text
явный DNS-клиент → UDP или TCP loopback stub
  → HTTPS POST /dns-query (TLS от stub до resolver)
  → transparent client → enc-SNI exit → origin TCP tap
  → локальный HTTPS resolver с синтетическими DNS-ответами
```

TLS заканчивается **на DoH resolver**, не на transparent client/exit. Relay
восстанавливает SNI и пересылает настоящий TLS приложения. Имя resolver (`localhost`
в fixture) отличается от пользовательского QNAME внутри зашифрованного HTTP body.
Resolver возвращает настоящие DNS wire messages, но не делает рекурсию: A —
`192.0.2.123`, AAAA — `2001:db8::12`. Эти IP не используются как сетевые назначения.
Checked-in сертификат/ключ предназначены только для тестов.

Используется DoH POST с `application/dns-message` по
[RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html), поверх HTTP/1.1/TLS 1.3.
GET/HTTP2 upstream, DoT и recursive resolver в этом пакете не реализованы.
DoH origin — узкая POST fixture, не полноценный сервер общего назначения.

Все подключения задаются числовыми loopback IP/портами. TLS servername и доверенный
CA заданы отдельно; `rejectUnauthorized:true` не отключается. Нет обращения к
системному DNS для bootstrap, выбора upstream по QNAME, HTTP redirects, proxy-env
или повторной попытки через UDP/TCP resolver. Неверный CA/hostname не допускает
отправки DNS HTTP body. Ошибка защищённого upstream даёт клиенту SERVFAIL.

## Поддержанный DNS subset

[Wire-модуль](lib/lab-dns-wire.mjs) проверяет header, одну IN-question A/AAAA,
границы labels/records, размеры A/AAAA RDATA, отсутствие trailing bytes, opcode,
QR, ID и соответствие question в ответе. Compression names в RR ограничены
backward pointers/128 шагами; циклы/выход за границы отвергаются. Questions с
compression, бинарные labels и другие qtypes пока не поддержаны.
Это bounded parser для стенда, не полный DNS validator и не DNSSEC implementation.
Непрозрачные RDATA других RR не получают полной семантической проверки.

DNS framing основан на [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html).
Для TCP используется двухбайтовая длина, проверены fragmentation, half-close и
две pipelined questions. Обработка запросов одного TCP-клиента последовательная.
Без EDNS UDP ограничен 512 байтами; с EDNS(0) payload size ограничивается диапазоном
512..4096. OPT framing/version/options проверяются, в синтетическом ответе
возвращается OPT. При большом ответе UDP получает TC и question, без частичного RR;
явный клиент может повторить запрос через TCP, который также идёт через DoH.
Основа EDNS — [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891.html).

DoH query ID нормализуется в 0; соответствие upstream response проверяется,
затем восстанавливается исходный ID клиента. NXDOMAIN и TTL, включая TTL=0,
передаются без кэширования. Каждый запрос создаёт отдельный HTTPS exchange/TLS
connection (`agent:false`); нет DNS cache, negative cache, shared HTTP cache,
HTTP Age обработки или connection pooling. Fixture использует `Cache-Control:
no-store`; этот subset не готов для произвольного кэширующего публичного DoH.
Некорректный DNS query UDP отбрасывается, TCP-соединение закрывается без upstream.

## Лимиты и отказы

| Ресурс | Default адаптера / harness |
| --- | --- |
| DNS wire message | 4096 байт, до 128 RR |
| HTTP response headers | 8192 байта |
| DoH deadline | 1500 / 1000 мс, programmatic 10..10000 мс |
| In-flight DoH | 16 / 8, максимальная настройка 64 |
| TCP DNS clients | 16 / 8, максимальная настройка 64 |
| TCP pending buffer | два максимальных frames, 8196 байт |
| TCP absolute lifetime | 5000 / 3000 мс, maximum 30 с |

Переполнение in-flight даёт SERVFAIL без очереди. TCP connections/buffer ограничены;
лишние sockets/oversized frames закрываются. Lifetime абсолютный, не продлевается
приходом байтов. TCP остаётся читаемым во время DoH с ограниченным буфером, чтобы
RST клиента отменял upstream request. Обычный FIN не означает отмену: DNS-ответ
может прийти после half-close. UDP не имеет сигнала отмены — действует deadline.

HTTP non-200 (включая redirect), неправильный media type, Content-Encoding,
слишком большой declared/chunked body, некорректный DNS body, ID/question mismatch,
сброс и зависание → SERVFAIL. Никакого downgrade/fallback. Timeout уничтожает request,
очищает timer; `close()` отменяет работу и **дожидается socket close events**.
Повторный close безопасен. Частичная ошибка запуска (например, занятый UDP-порт
после успешного TCP bind) откатывает созданные listeners.

`stats()` содержит только числовые счётчики/стабильные коды, не payload или QNAME:
inflight/peakInflight, requests/jobs/timers, TCP/TLS sockets, success/failure/rejected.
После cleanup owned requests/jobs/sockets/timers должны быть нулевыми.

## Что именно проверено про конфиденциальность

В lab добавлен опциональный `observeWire(stage, chunk, {peerPort})`: копии
входящих TCP-байтов в точках client, exit, origin. Default выключен; production
runtime не изменялся. Он продолжает наблюдение после ClientHello, поэтому видит
и TLS application records, а не только handshake.

Тест генерирует уникальный QNAME и собирает ограниченные byte streams по peer port
на участках client→exit и exit→resolver. Ответ подтверждает доставку question
resolver; в наблюдаемых байтах отсутствуют ASCII label и DNS wire name.
Отдельные spies запрещают реальное name resolution, неожиданные TCP endpoints
и UDP destinations при успехе, redirect и reset. Числовой `dns.lookup`, который
Node dgram вызывает для IP, разрешён: он не делает DNS lookup по имени.

Это **наблюдение TCP payload внутри процесса**, не независимый kernel pcap.
Проверяется направление запросов. Отдельного capture обратного направления,
всего внешнего интерфейса, OS/LAN/IPv6 трафика нет. Не следует выводить из этого
«вся система перестала раскрывать DNS». Resolver видит QNAME; локальный DNS stub
тоже получает plaintext query. Снаружи остаются видимыми IP, TLS metadata,
тайминги/размеры и resolver/public SNI соответствующего участка.

## Тесты и следующий шаг

46 регрессий: wire parser/EDNS, A/AAAA через UDP/TCP, fragmentation/pipelining,
TTL/NXDOMAIN, UDP TC→TCP retry, CA/hostname failures, reset/timeout/restart,
HTTP/DNS malformed responses, лимиты, abort/cleanup, startup rollback,
наблюдение QNAME и запрет неоговорённых DNS/TCP/UDP направлений, bounded CLI.
Набор включён в общий acceptance.

Проверено на VPS: **478 Node-тестов (21 файл) + 14 Chrome/Firefox-сценариев** —
PASS, без skips. Отдельно четыре real-browser soak/SIGTERM регрессии — PASS.
Самостоятельный CLI: 8 queries, 5 успешных DNS-ответов (включая NXDOMAIN),
3 ожидаемых SERVFAIL, по завершении owned sockets/requests/jobs/timers = 0.

Следующий отдельный пакет — независимый pcap в изолированной network namespace
с позитивным контролем утечки и ограниченный DNS soak. После этого — решение о
production upstream/bootstrap и отдельная интеграция с клиентом/OS/LAN/IPv6.
Декоративный cover DNS, системная перенастройка и расширение domain/IP admission
в этот результат не входят.

Файлы: [CLI](transparent-dns-lab.mjs), [harness](lib/transparent-dns-lab.mjs),
[stub](lib/lab-doh-stub.mjs), [wire](lib/lab-dns-wire.mjs), [tests](test-transparent-dns-lab.mjs).
