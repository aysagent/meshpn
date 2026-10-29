# Native combo: длительная нагрузка и сетевые помехи

Продолжение [контейнерного lifecycle](clean-vpn-native-combo-runtime.md),
2026-10-29. Только отдельная Linux-лаборатория; Radxa/VPS, системные службы,
Wi-Fi, DNS и маршруты Mac не изменяются. Тестируется production C++ engine с
настоящим TUN, native DNS, shared exit listener `3443` и durable replay volume.
Node генерирует прикладную нагрузку и управляет стендом; VPN data plane — native.

## Запуск

На выделенной Podman VM, с готовыми runtime и observer images:

```bash
CVPN_CONTAINER_COMMAND='["podman","--connection","meshpn-clean-vpn-lab-root"]' \
CVPN_RUNTIME_IMAGE=localhost/clean-vpn-native-runtime:combo-20261029 \
CVPN_OBSERVER_IMAGE=localhost/clean-vpn-native-observer:night-arm64 \
CVPN_COMBO_LOAD_SECONDS=900 CVPN_COMBO_NETEM=1 \
node scripts/clean-vpn-native-combo-runtime-lab.mjs /tmp/combo-resilience.json
```

`CVPN_COMBO_LOAD_SECONDS` — 30–1800 секунд штатной смешанной нагрузки, default 60.
`CVPN_COMBO_NETEM=1` добавляет фиксированные fault-фазы после неё. Неизвестное
значение отклоняется до создания ресурсов. Для Docker используется
`CVPN_CONTAINER_COMMAND='["docker"]'` на **выделенном Linux engine**. В приёмке
Docker работает внутри NIC-less контейнера Podman VM; публикаций на Mac нет.
Одновременно запускать две копии в одном engine нельзя: используются одни
лабораторные диапазоны `10.77.0.0/24`, `192.168.88.0/24`.

Отчёт и ownership-файл должны быть новыми. Каждые 30 секунд runner сообщает
прогресс. При долгом прогоне метрики снимаются примерно каждые 5 секунд,
коротком — каждые 250 мс плюс CLI overhead. Время жизни служебных контейнеров
растёт с заданной длительностью; прежний фиксированный TTL 1200 сек снят.
Прикладные логи внутри цикла подавлены, финальные counters обязательны:
длинный успешный прогон не должен падать из-за `execFile.maxBuffer`.

## Штатная нагрузка и ресурсы

В каждой итерации одновременно выполняются четыре relay HTTPS запроса и
packet-набор: DNS UDP/TCP, HTTPS с проверкой CA/hostname, TCP/UDP echo. Между
итерациями 500 мс, чтобы не превращать soak в постоянную перегрузку admission.
Каждая операция должна пройти. Отдельный burst из 64 relay запросов проверяет
ожидаемые отказы сверх production limits и работоспособность packet-ветки.

PID обоих engine должен оставаться прежним, native process — ровно один в
каждом контейнере, zombies — ноль. Sampled bounds: RSS <128 MiB, FD <128,
threads <48. После завершения FD/threads возвращаются к baseline, рост RSS
относительно baseline <32 MiB. Дополнительно медиана RSS последней трети
сэмплов сравнивается с первой третью: рост <8 MiB. Это ограничение измеренного
роста, не доказательство отсутствия всех утечек; короткие пики можно пропустить.

## Матрица помех

| Фаза | На каждом направлении client↔exit | Длительность нагрузки | Приёмка |
| --- | --- | --- | --- |
| delay | 60±10 мс, normal distribution | 30 сек | ≥90% успехов каждой ветки |
| loss | 20 мс и случайные потери 1% | 45 сек | ≥70% каждой ветки; drops >0 |
| reorder | 40 мс, reorder 25%, correlation 50% | 30 сек | ≥90% каждой ветки; рост TCP out-of-order counter |
| blackout | loss 100% | ≥8 сек | Ни одного успешного запроса, drops >0 |

В fault-фазах параллельны один packet-набор и два новых relay HTTPS запроса
за итерацию. Relay скачивает 256 KiB и проверяет длину и SHA-256. Повреждённое
содержимое не относится к допустимым сетевым отказам. TLS verification включена.
Каждый relay запрос ограничен абсолютными 8 сек; фаза заканчивается после
завершения последних запросов, поэтому её wall time может быть больше таблицы.
Ошибки и успешные попытки учитываются отдельно для обеих веток.

Netem устанавливается только на `eth0` созданных client/exit контейнеров:
`prio` + фильтр peer IPv4/TCP/3443. На клиенте фильтруется destination port,
на exit — source port; origin/LAN/ARP не получают помех. Перед добавлением
допустим только исходный `noqueue`; существующая чужая qdisc не заменяется.
Удаление в `finally` проверяет namespace и собственный handle. После каждой
фазы обе очереди должны снова быть `noqueue`.

Отчёт содержит реальные параметры и counters `tc -s -j qdisc`, TCP retransmits
и `TcpExtTCPOFOQueue` до/после. Для loss/blackout обязательны ненулевые drops,
для reorder — рост out-of-order counter. Это свидетельство воздействия на TCP;
здесь не измеряется точный процент переставленных сегментов на проводе.
[Документация netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html)
описывает ограничения таймеров и TSQ при egress emulation; этот стенд проверяет
корректность/восстановление, а не воспроизводит производительность WAN.

После удаления каждой помехи обязательны live DNS health, полный packet-набор
и HTTPS bulk relay. Затем FD/threads должны вернуться к исходному уровню за
30 секунд, PID не должен поменяться. Далее runner выполняет прежние проверки
relay без fallback, SIGKILL/recreate обеих сторон, replay persistence и SIGTERM.

## Доказательства и границы

Результаты фиксируются в `fixtures/clean-vpn-native-combo-resilience-20261029.json`.
Приёмка прошла: Podman soak/lifecycle **15/15**, NIC-less Docker netem/lifecycle
**19/19**, unit/regression **23/23**, без пропусков. Production image и бинарник
использованы прежние, пересборки engine не потребовалось.

- За 900 секунд: **6960 relay HTTPS запросов + 1740 packet-наборов**, все успешны.
  173 ресурсных сэмпла; peak RSS client/exit 6580/6812 KiB. Разница медиан первой
  и последней трети — +20/+8 KiB. FD вернулись к 8/8, threads к 3/2.
- Delay: 22/22 packet-набора и 44/44 bulk relay; loss: 61/61 и 122/122,
  netem зафиксировал 173 drops. Reorder: 32/32 и 64/64, out-of-order counter +341.
- Blackout: 0/3 packet и 0/6 relay; 37 drops. Возврат обеих веток после удаления
  каждой помехи занял 0.70–1.14 сек вместе с CLI/probe overhead, без рестарта PID.
  Проверки ресурсов, последующего SIGKILL/recreate и cleanup прошли.

Независимый pcap проверяет исходные ClientHello перед нагрузкой; это **не**
непрерывный capture всего soak/netem. JA3/JA4 не доказывают полную мимикрию браузера.
Admission/timeouts/ключи/production engine в этом этапе не ослабляются.
15 минут — ограниченная лабораторная приёмка, не многочасовая эксплуатация,
не multi-client capacity test и не физическая Radxa↔VPS проверка.

Продолжение: [offline combo bundle, active relay health и проверка трёх
независимых клиентов](clean-vpn-native-combo-provisioning.md). Обнаруженное
отсутствие relay fairness требует отдельной native-доработки identities/квот.
Переход к физическим узлам требует отдельного разрешения.
