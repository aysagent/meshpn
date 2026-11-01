# Native ClientHello record framing: кандидат исправления

Исходная задача — устранить отказ iPhone самостоятельно, используя сохранённую
запись и свежие TLS-сеансы, до повторной проверки на телефоне.
[Исследование и результаты](clean-vpn-native-iphone-cadence-20261101.md)
отделены от этого изменения. Причина сетевой фильтрации ещё не установлена.

## Основание для изменения

Один и тот же диагностический бинарник на Radxa, TCP_NODELAY, 20 исходных
публичных TLS-профилей Safari/zlib, оригинальные IP и темп:

| Вариант | Завершённый проверенный TLS | Остальные результаты |
| --- | --- | --- |
| Фрагментация исходных records до 512 байт перед SNI seal | 18/20 | два прежних handshake errors origin, один последующий HTTP read timeout |
| Следующий контроль без фрагментации | 11/20 | один handshake error origin, девять timeout, включая последующий read timeout одного проверенного TLS |

В контроле без фрагментации сначала исчезли ответы при полном ACK hello,
затем следующие соединения подтверждали только SYN. Это один положительный
парный эксперимент, не гарантия всех сетей или готовность iPhone к приёмке.
Программа генерировала новые private keys и завершала настоящий TLS с
проверкой CA/имени, а не останавливала старую запись на ServerHello.

## Реализация

На client transparent/combo длинные исходные records ClientHello делятся на
меньшие **до** SNI seal. Содержимое handshake, random, session ID, key shares,
список и значения extensions сохраняются. Исходные меньшие records и их
legacy version также сохраняются. Хеш в auth-токене связывает весь новый
prefix вместе с его framing. Exit восстанавливает исходное SNI и получает
именно этот связанный prefix; защита `relay_hello_binding` не ослабляется.

Это TLS record fragmentation, а не IP-фрагментация, TCP MSS clamp,
повторное соединение или fallback. Шифрование потока приложения и режим
boring-ветки не меняются. JA3/JA4 не содержат границы records; совпадение
отпечатков не означает побайтную идентичность полного браузерного поведения.

По умолчанию `client_hello_fragment_bytes=512`. Поле задаётся в JSON
transparent client (в combo — в объекте `transparent`); `0` сохраняет
исходный framing, положительные целые от 128 до 4096 задают размер payload
при делении исходных records. SNI seal затем удлиняет record-владельца имени,
поэтому 512 не является обещанием максимального размера records на WAN.
На exit это поле запрещено. Старые exit могут принять новый client: SNI
формат, auth, replay scope и исходный wire-binding алгоритм не менялись.

Сохраняются общие пределы hello/records, очереди и deadlines. Если добавленные
headers превышают существующие лимиты, запрос отклоняется до connect;
лимиты не увеличиваются и обходной путь не появляется.

## Проверка и состояние

Кандидат проверяется в изолированной Linux VM: сохранение handshake и
существующего малого framing, лимиты records/bytes, opt-out/schema,
auth round-trip и обязательный отказ при reframing **после** seal.
Настоящие TLS 1.2/1.3, HRR и resumed sessions проверяются отдельно;
socket-прогон использует большой PQ ClientHello для фактического деления.

Полная пересборка в ARM64 Linux VM и CTest **14/14** прошли. Реальные TLS:
12 комбинаций TLS 1.2/1.3, HRR, chunks и длинного имени, каждая full+resumed,
с проверкой сертификата и двунаправленными application bytes. Socket suite
с PQ hello прошёл: 2 MiB echo, 8 MiB slow consumer, auth-before-connect,
replay после restart, admission и half-close. В unit отдельно проверено,
что reframing после seal по-прежнему даёт `relay_hello_binding`.

## Физическая установка

Client `1888a5f` собран на Radxa в два потока с прежней оптимизацией и
ограничением памяти сборки. CTest **14/14**, 12 настоящих TLS combinations
full+resumed, 2 MiB echo и 8 MiB slow consumer прошли и на самой плате.

Перед обновлением прежний PID 57844 имел **5 ready events и 36 session ends**;
последний end — `h2_ping_timeout`. Это накопленная история предыдущих
исследовательских прогонов, а не нулевая исходная статистика. Новый процесс
обнуляет process-lifetime counters; это не является доказательством ремонта.

Бинарник установлен штатным updater с независимым rollback:
`6dd0dc966b65b97c810f64ed25877ed176cc6e8698e289c4b8231dcf58a87e7a`.
Новый client PID 145499 получил ready в 01:54:50 UTC. Pending journal отсутствует;
пять файлов config/ключей/профиля/CA совпали с исходными хешами. Guard активен,
network owner сохранил PID 736. Exit PID 894438 и его бинарник `70860bb`
не менялись; новые исходники доставлены Git fast-forward. Endpoint — **443**;
временных слушателей 3443 нет.

Перед этим отдельный диагностический прогон всех 182 fresh Safari/zlib
соединений с framing на Radxa дал **157 verified TLS**, 25 handshake errors
только для `iphone-ld.apple.com` (17) и `chat.m5stack.com` (8), а также один
HTTP read deadline **после** успешного TLS. Максимальный start drift — 13 ms.
Это прогон helper, его результат не подменяет проверку установленного клиента.

Независимый WAN observer при обновлении: kernel drops 0; cold boring profile
`chromium-156-bounded-cold-v1` — `matched`, `differences=[]`,
JA4 `t13d0915h2_f91f431d341e_54d72502093d`. В том же захвате 49 распознанных
Safari hellos имеют два ожидаемых JA3/JA4. Полный pcap и SNI остаются приватными.
DNS A/AAAA UDP/TCP через USB — **4/4**, native listener 10.99.0.2:1053 — **4/4**.

Полная fresh Safari/zlib-серия через **установленный клиент**, Mac en9 → USB
Radxa → native combo → VPS: **153/182 verified TLS**, 152 получили application
bytes, один HTTP read deadline произошёл после проверенного TLS. Для h2 эти
bytes могут быть SETTINGS; это не 152 доказанных HTTP-ответа.

Публичные параметры handshake/extensions проверены отдельно: **182/182**
совпадают с записью после исключения ожидаемо свежих random/key-share bytes,
SNI и GREASE values. Алгоритм certificate compression теперь точно zlib(1).
29 handshake errors: 17 `iphone-ld.apple.com` и два `example.org` с
`CERTIFICATE_VERIFY_FAILED`, восемь `chat.m5stack.com` и два `m.avito.ru` без
дополнительной TLS error string. В диагностике на Radxa было 25 ошибок, поэтому
нельзя переносить её 157/182 на installed client или называть все отказы
объяснёнными. CA verification нигде не выключена.

За серию новый packet-процесс сохранил **1 ready / 0 session ends**. После неё
relay active/pending=0, RSS 5508 KiB, 39 fd; это точка измерения, не длительный
memory soak. `failed` relay counter не равен числу незавершённых TLS: диагностика
закрывает короткие соединения после первых application bytes, включая RST;
поэтому в журнале остаются encrypted-stream errors. Не выдавать их за ноль.

Через отдельный Chrome → USB proxy полный Speedtest завершился:
**44,49/44,43 Мбит/с**, ping **88 ms**. Его WebSocket на 8080 использует
packet-ветку. Отдельно именно через HTTPS **443** проверены 2 и 8 MiB download
и 2 MiB синтетического upload: HTTP **200**, точные размеры и verify result 0.
Во время этих проверок packet session ends оставался 0, guard/network не менялись.
`internet.yandex.ru` в том же Chrome получил HTTP 200 и завершил измерение:
**26,07/95,10 Мбит/с**, ping **105 ms**. Это отдельные измерители и пути;
цифры не являются строгим сравнительным benchmark.

Отдельные диагностические контроли уточнили остаточные ошибки: оба ранее
отказавших `m.avito.ru` завершили TLS за 599/2290 ms; у двух `example.org`
и одного представителя `iphone-ld.apple.com` verify code **20** —
`unable to get local issuer certificate` в явно выбранном `/etc/ssl/cert.pem`
диагностической программы Mac. Это не проверка trust store iPhone/Safari.
`chat.m5stack.com` снова дал SSL_ERROR_SYSCALL/EOF до завершения TLS;
его отдельная причина не установлена. Никакой CA/system trust не меняли.

Во время браузерных тестов несколько DNS upstream timeout были успешно
повторены штатным DNS-механизмом (три к моменту завершения замера Яндекса);
не называть diagnostics совершенно безошибочными.

После завершения браузеров и автоматического закрытия временного USB proxy:
PID тот же, **1 ready / 0 session ends**, 389 relay accepted, active/pending=0,
3 threads, 9 fd, RSS 9040 KiB. Пиковая relay queue — 147456 bytes,
admission dropped=0. Временные процессы/слушатели проверки завершены;
Mac system network, DNS, proxy и trust не менялись.

[Санитизированные результаты](../fixtures/clean-vpn-native-hello-framing-20261101.json).

Исходную приёмку физического iPhone не объявлять закрытой. Повтор телефона
не запрашивается вместо самостоятельного воспроизведения и исправления.
