# DNS wire contract адаптера

Общий модуль `lib/lab-dns-wire.mjs` используется explicit client→exit adapter и
старым DNS lab. Это bounded forwarder, не recursive resolver и не DNSSEC validator.
Никакого переключения OS DNS, TUN, firewall или прямого fallback этот слой не делает.

## Что поддержано

- Один вопрос IN, opcode QUERY: A/AAAA, NS/CNAME/SOA, PTR, MX, TXT, SRV,
  DNAME, HTTPS/SVCB, CAA, DNSSEC RR и неизвестные обычные типы.
- Проверка header, question, owner names, RR/OPT lengths, счётчиков, конца сообщения,
  ID и соответствия question в ответе. Для A/AAAA также проверяется длина RDATA.
  Остальные RDATA передаются **непрозрачно**: адаптер не проверяет содержимое
  SvcParams, подписи DNSSEC, корректность TXT/SRV/SOA или смысл ECH-параметра HTTPS.
- Полные ответы сохраняются побайтно, кроме временной нормализации ID в0 на DoH
  участке и восстановления ID локального клиента. Это сохраняет compression
  pointers и неизвестные расширения. Непрозрачная передача следует принципу
  [RFC3597](https://www.rfc-editor.org/rfc/rfc3597.html#section-3).
- Бинарные DNS labels, корневое имя, ASCII-only case-insensitive matching;
  границы labels учитываются, `a.b` внутри одной label не равен двум labels.
  Основа сравнения — [RFC4343](https://www.rfc-editor.org/rfc/rfc4343.html).
- EDNS(0): один OPT с корневым owner в additional section, проверка длин options,
  неизвестные options/DO передаются без изменения. Расширенный 12-битный RCODE,
  включая BADVERS, сохраняется. Ответ с OPT без OPT в запросе отвергается.
- UDP:512 байт без EDNS; объявленный размер ограничен диапазоном512..4096.
  Большой ответ → TC с исходным question, полным RCODE и пустым OPT, если запрос
  был EDNS. Нет частичных RR или указателей на удалённые данные. RD/CD/RA берутся
  из ответа; AA/AD сбрасываются для синтетического ответа. Request options не
  копируются в локальную ошибку/TC. Основа EDNS —
  [RFC6891](https://www.rfc-editor.org/rfc/rfc6891.html).
- Клиент может повторить запрос по TCP к тому же stub: запрос снова идёт через
  защищённый DoH, полный ответ возвращается в пределах общего лимита4096.
  Upstream TC не запускает прямой DNS fallback. Неполный RR не принимается даже с TC.

## Явные ограничения пилота

Максимум4096 байт на запрос/ответ и128 RR; DNS names≤255 байт,
label≤63 байт, compression только назад, максимум128 шагов. Сжатые questions
не принимаются. Не поддержаны другие classes/opcodes, multi-question, EDNS
версии>0 и QTYPE0/41/249..255/65535 (meta, transfer, ANY, reserved). Это локальная
политика пилота, **не полная реализация прозрачного DNS proxy**. Invalid/unsupported
запросы отбрасываются до соединения с exit (TCP закрывается); при ошибке upstream
валидный запрос получает SERVFAIL. На EDNS version>0 пока нет локального BADVERS.

Лимит4096 действует также для TCP/DoH: большие корректные ответы дают SERVFAIL,
а не автоматически открывают другой путь. DNSSEC records и AD/CD/DO передаются,
но адаптер сам не проверяет подписи. Нет cache/pooling, обработки HTTP Age/TTL
для произвольного кэширующего upstream или автоматического TCP retry за клиента.

Следующий этап перед OS integration: ограниченная поддержка полного TCP/DoH
размера DNS65535 с отдельным UDP cap и пересчитанными memory/framing budgets;
EDNS version negotiation и HTTP cache-age/TTL contract. Затем согласование
opt-in client/OS/LAN/IPv6 lifecycle и восстановления настроек при отказах.

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
Это синтетический resolver, не проверка совместимости со всеми внешними DNS.
