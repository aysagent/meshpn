# DNS adapter: независимый pcap и ограниченный soak

Проверяет **новый in-memory client→exit путь** из `dns-exit-adapter.mjs`, а не
старый lab TLS через локальный HTTPS listener. Никаких внешних resolver,
работающего VPN, TUN, host routes/firewall/system DNS. Реальный TLS1.3 и HTTP,
настоящие public-contract профили и pinned route, без отключения проверки CA.

```bash
npm run dns:adapter-soak -- --seconds=300 --concurrency=4 --family=4 --mode=transparent-tls
npm run dns:adapter-soak -- --seconds=300 --concurrency=8 --family=6 --mode=combo-tls

npm run test:dns-adapter-soak
npm run test:dns-adapter-soak-real
```

Нужны Linux user/net/mount/PID namespaces, Node (проверено24.13.0), `ip`, OpenSSL,
tcpdump и tshark. Пути можно задать `MESHPN_TCPDUMP` / `MESHPN_TSHARK`; для
извлечённых библиотек — `LD_LIBRARY_PATH`. Ничего не скачивается и не устанавливается.
Отсутствие инструмента/прав namespace — **fail**, не skip или ослабленная проверка.

Все адреса жёстко заданы fixture и назначаются только на `lo` внутри отдельного
namespace: публичные IPv4/IPv6 aliases для exit, первого отказавшего кандидата и
resolver. В namespace нет uplink; перед созданием адресов проверяются namespaces,
PID1 и отсутствие других интерфейсов. CLI не принимает адреса/PSK/production config.

Параметры: seconds1..600 (default60), concurrency1..8 (default4), family4/6,
mode transparent-tls/combo-tls. Mode — метка общего runtime exit, **не запуск
full clean-vpn/TUN/combo mux**. Семейство меняет реальные TCP endpoints, не тип
DNS-ответа; A и AAAA проверяются в обоих случаях. Parent deadline: seconds+60с.
Подготовка, pcap,10 warmup waves и cleanup не входят в измеряемые seconds.

## Независимый pcap

tcpdump захватывает **весь TCP/UDP namespace**, не фильтрует только ожидаемые
порты. `-s0`, пакетный/файловый/выходной бюджеты; tshark читает numeric поля
без name resolution и TLS secrets. Контрольный открытый UDP DNS-запрос и ответ
с тем же случайным QNAME обязаны обнаруживаться. Plaintext у loopback stub также
ожидается; на client→exit и exit→resolver ищется утечка в **обоих направлениях**.

Аудит проверяет точные address+port tuples пяти назначений: stub, контроль,
exit, resolver, отказавший кандидат. Чужой peer/endpoint, UDP на TLS-участке,
payload на отказавшем кандидате, отсутствие направления или положительного
контроля → fail. TCP собирается по stream/direction/sequence: разрезанный по
сегментам QNAME не обходит проверку; идентичные retransmits допустимы, gaps,
conflicting overlap, пропущенный prefix, усечённые пакеты и kernel drops — fail.
Число строк tshark должно совпасть с числом захваченных пакетов tcpdump.

Capture включает успешные A/AAAA UDP/TCP, ошибки HTTP/обрывы, недоступность
resolver и exit, принятый, но молчащий exit, перегрузку и отмену. Это короткая
проверка перед soak, **не непрерывный pcap всех пяти минут**. Проверяется отсутствие
буквального случайного QNAME marker; это не доказательство отсутствия всех
возможных побочных каналов. В одном worker нельзя по pcap доказать авторство
разрешённого origin-соединения: дополнительно сверяются точные TCP dial/body
счётчики, а отдельные adapter-тесты проверяют единственный клиентский dial в exit.

## Нагрузка и контроль ресурсов

Один adapter живёт весь прогон. Цикл включает:

- normal/NXDOMAIN/large с TC→возможностью TCP retry, reset, hold, HTTP redirect,
  выключенный resolver и восстановление;
- закрытый listener exit, принятый TCP без TLS-ответа, обрыв активного exit;
- заполнение in-flight лимита, лишний запрос с SERVFAIL **без нового dial**;
- TCP-клиент отменяет запрос после получения DNS body resolver; все связанные
  соединения и таймеры должны освободиться.

Fixture deadline250мс ускоряет fault injection; это не изменение default1500мс
пилотного adapter. Весь сценарий повторяется10 раз для прогрева, затем в течение
заданного времени. В каждом завершённом цикле проверяются реальные counters и
нулевые idle sockets/jobs/timers/sessions. Измеряются fd, RSS, heapUsed, active
resources и процессы в приватном `/proc`, а не процессы пользователя на хосте.

Worker запускается с V8 old-space64MiB/semi-space8MiB, без принудительного GC.
Бюджеты: RSS≤256MiB, fd≤128; idle fd не выше baseline после прогрева; рост RSS
≤64MiB и heapUsed≤32MiB относительно наблюдаемого warmup high-water. Каждый цикл
проверяется, report сохраняет выборку примерно раз в5с и финал. Replay cache
измеряется отдельно: его ограниченное удержание записей601с ожидаемо и не
считается утечкой, очистка между запросами не подменяет реальный runtime.

После cleanup: ноль owned sockets/jobs/timers, TCP/UDP listeners, дочерних
процессов и zombies. Parent сверяет длительность, семейство/mode, число циклов,
ответы/ошибки/отмены/отказы перегрузки, исходящие соединения, попытки pinned IP,
полученные resolver bodies и ресурсные бюджеты. «Процесс завершился с0» недостаточно.

## Отчёт и отмена

Путь к JSON печатается при запуске. `--report=/existing/dir/new-report.json`
создаёт **новый** файл с правами0600 и не перезаписывает существующий/symlink.
Report содержит Git revision/dirty, Node/V8 limits, параметры, pcap summaries,
измерения и redacted failure phase/code; без QNAME, PSK, сертификата/ключа,
сырых пакетов и stack. Raw pcap и временные PEM удаляются вместе с собственным
приватным временным каталогом после окончания, в том числе при ошибке.

SIGINT/SIGTERM → остановка worker process group, cleanup и `aborted`, ненулевой
exit. Parent ограничивает stdout/stderr и время; авария/SIGKILL/OOM могут лишить
нас полного worker отчёта, что не считается успехом. Внешний report сохраняется,
но при SIGKILL самого parent финальная запись/удаление не гарантируются.

Успешный ограниченный прогон — свидетельство для данных сценариев и окружения,
не доказательство отсутствия утечек памяти навсегда и не production-сертификация.
System/LAN DNS, остальные DNS-типы и интеграция с IPv6/kill-switch остаются
отдельной работой. Старый `transparent-tls:dns-soak` сохранён для своего lab пути.

## Зафиксированный прогон 2026-09-23

Оба прогона PASS; SERVFAIL, отказы и отмены ниже намеренно вызваны fault injection,
а не проигнорированы как «допустимые ошибки». Счётчики совпали точно.

| Измеряемая фаза | IPv4 / transparent / concurrency4 | IPv6 / combo / concurrency8 |
| --- | --- | --- |
| Длительность | 300.055с | 301.050с |
| Циклы | 279 | 228 |
| Ответы / из них ожидаемые SERVFAIL | 13671 / 9207 | 22116 / 14820 |
| Перезапуски listeners | 558 | 456 |
| Отказы из-за заполненного лимита / отмены TCP | 279 / 279 | 228 / 228 |
| Пакетов в отдельном pcap smoke | 1631 | 3119 |
| Максимальный sampled RSS / heapUsed | 106.93 / 21.99MiB | 107.93 / 23.42MiB |
| Рост от warmup high-water: RSS / heapUsed | 6.06 / 3.09MiB | 6.11 / 3.01MiB |
| Idle baseline fd → после cleanup | 23 → 19 | 23 → 19 |

После cleanup в обоих случаях owned sockets/jobs/timers/sessions/listeners=0,
дочерних процессов/zombies=0; OS DNS lookup на pinned route=0. Replay cache
содержал11893/19362 записей в штатном окне удержания; это учтено в памяти.
Pcap positive control и обе стороны защищённых legs прошли аудит; неожиданных
endpoints и plaintext marker на них не обнаружено. Временные pcap/PEM удалены.

Reports на стенде: `/var/tmp/meshpn-dns-soak-report-3Pl6Ou/report.json` и
`/var/tmp/meshpn-dns-soak-report-Libb6L/report.json`. Они привязаны к текущему
хосту; не содержатся в git. Эти числа не являются throughput benchmark WAN.
