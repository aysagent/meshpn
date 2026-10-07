# Native combo: смешанная нагрузка и ресурсы

Результат 2026-10-07: **180 секунд**, 2 437 092 проверенных пакета и 1 907
TLS-сеансов, 0 потерь boring-пакетов и 0 неожиданных packet reconnect.
Пиковый RSS client/exit — 4 896/5 140 KiB, рост после прогрева — 20/136 KiB.
FD вернулись к 6/8, threads — к 2/2. Отдельный 30-секундный ASAN/UBSAN
прогон также прошёл. Регрессия **418/418** (legacy-exit soak выключен,
исторические compatibility tests сохранены), CTest normal/ASAN **6/6**,
ASAN combo/transparent/soak **10/10**. Запуски пересекались с другими тестами;
числа CPU/объёмов не подходят для сравнения скорости.
[Полный отчёт и hashes](fixtures/clean-vpn-native-combo-soak-report.json).

Стенд проверяет native client и exit одновременно: непрерывная передача IPv4
пакетов в обе стороны через boring-ветку и повторные TLS 1.2/TLS 1.3-HRR
соединения через transparent-ветку того же exit-порта. Длительность по умолчанию
180 секунд, допустимый диапазон 10–600 секунд. Все данные генерирует и проверяет
C++ fixture; Node запускает процессы и проверяет итоговый JSON, без передачи
пакетов или TLS-данных в Node.

```bash
cmake --build native/clean_vpn/build --target \
  clean-vpn-engine-fixture transparent-socket-test -j2
node --test scripts/test-native-combo-soak*.mjs
```

Для уже подготовленной sanitizer-сборки:

```bash
cmake --build native/clean_vpn/build-asan --target \
  clean-vpn-engine-fixture transparent-socket-test -j2
ASAN_OPTIONS=quarantine_size_mb=16:thread_local_quarantine_size_kb=256 \
CVPN_BUILD=native/clean_vpn/build-asan CVPN_COMBO_SOAK_SECONDS=30 \
  node --test scripts/test-native-combo-soak*.mjs
```

ASAN quarantine ограничен явно: стандартный отложенный возврат освобождённых
allocation при частом создании тестовых пакетов сам расходует сотни MiB.
Sanitizer-результат не используется как оценка production памяти/скорости.

## Критерии

- Каждый пакет размером 1400 байт проверяется побайтово на противоположной стороне.
  Пакеты идут поочерёдно в обе стороны с одновременным TLS-потоком.
- Каждый TLS-сеанс передаёт 1 MiB и получает точное echo, затем проверяет
  close-notify/half-close. Версии чередуются; сертификат и hostname проверяются.
  Origin допускает только P-256, клиент предлагает X25519 первым: TLS 1.3 идёт с HRR.
- Все TLS-сеансы должны завершиться; origin не должен иметь failed-соединений.
- У каждой boring-ветки ровно один `ready`, generation 0, точные TX/RX counters
  и 0 dropped packets. Финальные counters учитывают отдельную пару warmup-пакетов.
- Примерно раз в секунду читаются `/proc` обоих engine: RSS, CPU ticks, количество
  FD и threads. Пределы: RSS <256 MiB, рост RSS после прогрева <64 MiB,
  не более 96 FD/48 threads. Первые 5 секунд используются для прогрева.
- После окончания TLS-нагрузки число FD и threads обоих процессов должно вернуться
  к исходному, **до** остановки любого peer. Затем обе роли штатно завершаются.
- Неполный отчёт, ошибки содержимого/counters, reconnect, отсутствие одной TLS-версии,
  превышение ресурсов или незавершённый прогон не принимаются.

## Изоляция и границы

Новый пустой user/network namespace; перед сетевыми изменениями C++ проверяет
отличие netns от родителя и единственный интерфейс `lo`. Внешней сети нет.
Вместо TUN — socketpair packet FD специального fixture engine; production engine
такой вход не поддерживает. Настоящие TLS, REDIRECT и durable replay используются,
но здесь нет real-TUN/DNS/systemd/reboot или независимого leak capture: эти
сценарии проверены отдельными network/boot стендами.

Это sustained mixed-load и churn-проверка, не saturating throughput benchmark,
не WAN Speedtest и не многоклиентная/многочасовая приёмка. TLS-поток один за раз,
origin искусственно замедляет чтение; packet-путь stop-and-wait. RSS — не PSS,
сэмплирование может пропустить короткие пики. Возврат FD/threads и ограниченный
рост памяти за этот интервал не являются доказательством отсутствия всех утечек.
