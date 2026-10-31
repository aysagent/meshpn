# Radxa ↔ VPS: рабочий combo endpoint переведён на 3443

2026-10-31, после явного подтверждения пользователя «переключи».

Рабочая пара теперь использует `154.62.226.216:3443` для обеих веток combo.
Изменены только поля:

- exit `/opt/clean-vpn-native/combo-daily-exit/config.json`:
  `boring.port`, `transparent.listen.port` — 443 → 3443;
- client `/opt/clean-vpn-native/combo-daily/config.json`:
  `boring.port`, `transparent.exit.port` — 443 → 3443.

Оба отдельных candidate проверены установленным `engine --check-config`.
Перед применением каждый candidate сравнен с актуальным конфигом: допустимы
только эти два изменения. Сохранены приватные резервные копии, затем рабочие
конфиги заменены атомарно с fsync. Перезапущены только native engine units,
без перезапуска владельцев маршрутов. Ключи, CA, SNI, выбранный профиль,
DNS, маршруты и правила guard сохранены. Промежуточный TCP proxy не установлен:
3443 слушает сам native exit.

Резервные копии `config-before.json` и метаданные `change.json`:

- VPS: `/var/lib/clean-vpn-port3443-sejys5ys/`;
- Radxa: `/var/lib/clean-vpn-port3443-8e_1iixx/`.

Для отката нужны обе исходные конфигурации и перезапуск соответствующих engine
units. Односторонний откат оставит несовпадающие endpoint-порты.

## Что наблюдалось до смены порта

Автономная запись после загрузки содержит запросы USB iPhone. DNS Yandex
получал ответ, ClientHello поступал в local REDIRECT, но ServerHello телефону
не возвращался; примерно через 10 секунд relay закрывал соединение.

Одновременные tcpdump Radxa/VPS сопоставлены по TCP sequence numbers:
Radxa отправляла два сегмента ClientHello, VPS видел только первый (1288 байт).
Отправленный VPS ACK первого сегмента отсутствовал в записи Radxa; на Radxa
продолжались retransmissions. INPUT/OUTPUT VPS имели ACCEPT, служба слушала.
Отдельные короткие и длинные TLS ClientHello (517 и 1614 байт) через временный
ограниченный byte-echo на 3443 возвращались полностью. На 443 TLS probes
зависали. Уменьшение TCP_MAXSEG и разбиение TLS records не помогли.

Это свидетельство проблемы пути для наблюдавшихся соединений на 443,
не точная атрибуция оператору, hotspot, DPI или конкретному устройству.
Диагностический echo завершён; постоянно работающего echo/proxy нет.

## Проверки после переключения

Физическая Radxa: `native-combo-daily.service` active, StatusText ready,
реальный TCP socket к exit:3443 ESTABLISHED. Exit native listener:3443 active.
Владелец сети и kill switch active. Админка читает новый endpoint из конфига.

С Mac через привязку отдельных сокетов к USB en9, без изменения настроек Mac:

- `https://internet.yandex.ru` с переходом на `https://yandex.ru/internet/`: HTTP 200;
- `https://www.speedtest.net`: HTTP 200;
- `https://example.org`: HTTP 200;
- DNS UDP и TCP к 1.1.1.1: NOERROR, непустые A-ответы;
- HTTPS POST через httpbin.org: HTTP 200, 276000 синтетических байт переданы
  за 2.64 с; echo body совпал побайтно, SHA256
  `5cef619c45fdf543420c71a348fcc260439553c7518da4ed6d9e8f41ffed2567`.

Это проверка загрузки страниц и конкретной HTTPS-отправки, не полный benchmark
Speedtest и не подтверждение исправления iPhone до повторного физического теста.
Автономная запись остановлена, её автозапуск отключён. Сами рабочие конфиги
сохраняют порт 3443 после перезагрузки; холодный старт с новым портом отдельно
не проверен. Старые экспорты других клиентов с портом 443 требуют обновления.
