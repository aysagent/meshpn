# DNS wire contract адаптера

Общий модуль `lib/lab-dns-wire.mjs` используется explicit client→exit adapter и
старым DNS lab. Это bounded forwarder, не recursive resolver и не DNSSEC validator.
Никакого переключения OS DNS, TUN, firewall или прямого fallback этот слой не делает.

## Что поддержано

- Один вопрос IN, opcode QUERY: A/AAAA, NS/CNAME/SOA, PTR, MX, TXT, SRV,
  DNAME, HTTPS/SVCB, CAA, DNSSEC RR и неизвестные обычные типы.
- Проверка header, question, owner names, RR/OPT lengths, счётчиков, конца сообщения,
  ID и соответствия question в ответе. Для A/AAAA также проверяется длина RDATA.
  Остальные RDATA передаются **непрозрачно**, кроме чтения MINIMUM из SOA
  отрицательного ответа для расчёта TTL: адаптер не проверяет содержимое
  SvcParams, подписи DNSSEC, корректность TXT/SRV или смысл ECH-параметра HTTPS.
- Полные ответы сохраняются побайтно, кроме временной нормализации ID в0 на DoH
  участке, восстановления ID клиента и уменьшения RR-header TTL. Это сохраняет compression
  pointers и неизвестные расширения. Непрозрачная передача следует принципу
  [RFC3597](https://www.rfc-editor.org/rfc/rfc3597.html#section-3).
- Бинарные DNS labels, корневое имя, ASCII-only case-insensitive matching;
  границы labels учитываются, `a.b` внутри одной label не равен двум labels.
  Основа сравнения — [RFC4343](https://www.rfc-editor.org/rfc/rfc4343.html).
- EDNS(0): один OPT с корневым owner в additional section, проверка длин options,
  неизвестные options/DO передаются без изменения. Расширенный 12-битный RCODE,
  включая BADVERS, сохраняется. Ответ с OPT без OPT в запросе отвергается.
  Для версии запроса1..255 stub возвращает локальный BADVERS с version0 и пустым
  OPT **до in-flight admission и без соединения с exit**. Автоматического повторения
  запроса/отключения EDNS нет. Повреждённый OPT по-прежнему отвергается.
- UDP:512 байт без EDNS; объявленный размер ограничен диапазоном512..4096.
  Большой ответ → TC с исходным question, полным RCODE и пустым OPT, если запрос
  был EDNS. Нет частичных RR или указателей на удалённые данные. RD/CD/RA берутся
  из ответа; AA/AD сбрасываются для синтетического ответа. Request options не
  копируются в локальную ошибку/TC. Основа EDNS —
  [RFC6891](https://www.rfc-editor.org/rfc/rfc6891.html).
- Клиент может повторить запрос по TCP к тому же stub: запрос снова идёт через
  защищённый DoH, полный ответ возвращается в пределах лимита65535 байт.
  Upstream TC не запускает прямой DNS fallback. Неполный RR не принимается даже с TC.

## HTTP Age и DNS TTL

Запрос содержит `Cache-Control: no-cache, no-store`; локальный HTTP/DNS cache не
добавлен. Заголовок `Age` всё равно учитывается: директива запроса не гарантирует
свежий ответ. Из TTL каждого обычного RR во всех трёх секциях вычитается Age плюс
целые секунды измеренного monotonic времени HTTPS exchange (включая тело).
Нижняя граница0; TTL с установленным старшим битом считается0. Это консервативное
уменьшение, а не продление lifetime по Date/Expires/Cache-Control. Принцип Age —
[RFC8484 §5.1](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1), границы TTL —
[RFC2181 §8](https://www.rfc-editor.org/rfc/rfc2181.html#section-8).

Age должен быть одним полем с неотрицательным десятичным целым; проверяются raw
headers, чтобы не пропустить дубликат после нормализации Node. Invalid/duplicate
Age → SERVFAIL без fallback. Отсутствующий Age считается0; переполнение насыщается
на2^31 секунд согласно [RFC9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2).

TTL SOA в Authority для NOERROR/NXDOMAIN консервативно ограничивается
`min(SOA TTL, SOA MINIMUM)` **до вычитания возраста**. Два имени SOA и20 байт
полей проверяются перед чтением MINIMUM; malformed SOA → SERVFAIL.
Основа negative caching — [RFC2308](https://www.rfc-editor.org/rfc/rfc2308.html).
Это действует и при CNAME chain в Answer; пустой Answer не требуется.
Сам SOA RDATA, RRSIG Original TTL, signatures, OPT flags/extended RCODE и остальные
RDATA не переписываются; AA/AD полного ответа сохраняются, но это не локальная
проверка DNSSEC. TTL0 может быть возвращён клиенту; собственного кэша/повтора нет.

## Лимиты памяти и framing

TCP/DoH query/response≤65535, UDP input/output≤4096, максимум128 RR в сообщении.
DoH body копируется в один фиксированный buffer65535, без списка мелких chunks.
Content-Length>65535 отвергается до чтения тела, chunked overflow — при превышении.
На каждый допущенный TCP socket выделяется фиксированный input buffer131074
(два frames с двухбайтовой длиной); без повторного concat растущего буфера.
Переполнение закрывает socket и отменяет текущий DoH. На socket одновременно
обрабатывается один запрос; output write callback управляет переходом к следующему.
Absolute deadline/lifetime и caps16 in-flight/16 sockets (настраиваемые до64)
сохранены. `peakTcpPendingBytes` и `peakDohBodyBytes` доступны в stats.

Консервативный бюджет собственных DNS payload buffers при default caps — до6MiB:
input + отделённый query + output frame на TCP socket, нормализованный query +
body на in-flight DoH. При caps64 — до24MiB. Это **не общий RSS bound**:
TLS/Node/kernel/JS имеют свои расходы; общий RSS/heap/FD отдельно проверяются soak.

## Явные ограничения пилота

DNS names≤255 байт,
label≤63 байт, compression только назад, максимум128 шагов. Сжатые questions
не принимаются. Не поддержаны другие classes/opcodes, multi-question и
QTYPE0/41/249..255/65535 (meta, transfer, ANY, reserved). EDNS версии>0 не пересылаются.
Это локальная
политика пилота, **не полная реализация прозрачного DNS proxy**. Invalid/unsupported
запросы отбрасываются до соединения с exit (TCP закрывается); при ошибке upstream
валидный запрос получает SERVFAIL (исключение для нового EDNS — локальный BADVERS).

Размер65535 не снимает лимит128 RR: более многочисленные ответы дают SERVFAIL.
DNSSEC records и AD/CD/DO передаются, но адаптер сам не проверяет подписи. Нет
cache/pooling, HTTP cache revalidation или автоматического TCP retry за клиента.

Следующий этап — согласование opt-in client/OS/LAN/IPv6 lifecycle и восстановления
настроек при отказах; сначала dry-run/изолированный стенд, не переключение live OS.

## Проверки

```bash
node --test scripts/test-dns-wire.mjs
npm run test:dns-exit-adapter
npm run transparent-tls:acceptance
```

Wire-набор проверяет21 обычный тип, policy exclusions, бинарные labels и matching,
границы размеров, OPT/options, extended RCODE, upstream TC и безопасное усечение.
Adapter-набор гоняет A/AAAA/PTR/TXT/SRV/SVCB/HTTPS/TYPE65280 через UDP и TCP,
настоящий TLS client→exit→resolver, проверяя весь ответ побайтно. Отдельный сценарий
проверяет большой HTTPS ответ: UDP TC с extended RCODE → TCP полный ответ.
Дополнительно: TXT4096/4097/65535, максимальный padded TCP query, HTTP overflow,
local BADVERS, Age/negative SOA, медленное тело, pending-buffer overflow/cancellation.
Public-contract namespace matrix повторяет большие ответы/запросы, BADVERS и Age
для IPv4/IPv6 × transparent/combo вместе с CA/failover/recovery/cleanup.
Это синтетический resolver, не проверка совместимости со всеми внешними DNS.
