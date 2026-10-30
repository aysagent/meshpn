# Тридцать минут combo на точном daily binary

После ремонта админки рабочая пара Radxa/VPS оставлена в покое. Её ARM64 engine
скопирован read-only и проверен в отдельных контейнерных namespaces. SHA256:
`fcdacc399607bc5cec2d5ec4ed18670d66d349513678c485773c06cc2e5e5c1d`.
Это прежняя принятая сборка, без новых native diagnostic counters.

[Полная приёмка с image ID, samples и cleanup](../fixtures/clean-vpn-native-daily-soak-20261031.json).

- Четыре независимых клиента/LAN, разные packet и relay keys, один combo exit
  на `3443`, настоящие TUN и bounded Chromium-derived profile.
- **1800 секунд**, **14073 успешных mixed rounds**: 3520/3519/3517/3517 на клиента.
  В каждом round одновременно packet-набор и новый relay HTTPS запрос.
  312 resource samples; native PID не менялся, zombies не обнаружены.
- Во время обычной нагрузки sampled RSS exit не превысил 6516 KiB, клиентов —
  6080–6096 KiB. Изменение медианы первой/последней трети: exit +8 KiB,
  все клиенты 0 KiB. Это дискретные RSS samples, не вся память ядра/контейнера.
- Удержание 64 relay slots одной identity блокирует её следующий relay, но
  каждый из остальных трёх клиентов прошёл 8 packet и 8 relay probes без отказов.
  Это проверка одной quota, не защита от нескольких согласованно действующих identities.
- После pressure FD/threads вернулись к baseline. RSS exit после pressure —
  12284 KiB, первого клиента — 7324 KiB: не путать с пиками **обычной** нагрузки.
  Все native PID1 завершились штатным SIGTERM; свои containers/volumes/bridges удалены.

Стенд использует Ubuntu runtime с hash-checked artifact, отдельную CA/имена и
контейнерные IP. Private `.mpn` и address discovery не включены. Исходный binary
не пересобирался, поэтому результат относится именно к указанному SHA, а не
к последующим source changes. Wire/JA3/JA4 capture в этот soak не включён.

На той же Podman VM параллельно шли сборка и небольшие изолированные тесты.
Это проверка устойчивости и освобождения ресурсов, не сравнение latency или
скорости транспорта. Настройки сети Mac и физические VPN-сервисы не менялись.
