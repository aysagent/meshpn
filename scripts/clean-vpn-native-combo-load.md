# Native combo: длительная нагрузка через real TUN

Проверено 2026-10-07: два успешных прогона, **14/14 gates** каждый. Последний —
40 раундов за 182,3 секунды: 40 MiB TCP echo, 80 MiB TLS echo, 200 UDP datagrams,
160 DNS queries, 82 445 дополнительных TUN packets. Это объёмы тестовой нагрузки,
не оценка пропускной способности. У обеих ролей 0 engine drops, один `ready`,
generation 0 и совпадающие встречные TX/RX. Peak RSS client/exit — 6 828/6 400 KiB,
FD вернулись к 8/8, threads — к 3/2. Selected-origin capture: 456 пакетов прямого
положительного контроля до guard, 0 direct после guard, 0 kernel capture drops.

Регрессия **429/429**, CTest normal/ASAN **6/6** в каждой сборке. Изменены только
лаборатория/проверки, не production C++ engine. [Отчёт, оба прогона и hashes](fixtures/clean-vpn-native-combo-load-report.json).

Отдельный режим существующей NIC-less network VM:

```bash
node scripts/clean-vpn-native-lab.mjs \
  /absolute/path/to/verified-host-boot-base \
  /absolute/path/to/qemu-tools-root --native-combo-load
```

Нужны проверенный base image и собранные production `clean-vpn-engine`, C++
`socket-test` и `transparent-socket-test`. Доступа к физической сети нет, драйвер
отказывает вне QEMU с нужными kernel markers и исходной сетью только из `lo`.
VM имеет настоящий TUN у native client и exit, LAN и отдельный origin namespace.

## Нагрузка

В течение минимум 180 секунд повторяются раунды. В каждом параллельно запущены:

- C++ TCP/UDP/DNS-проба: 1 MiB TCP echo, пять UDP datagrams размером
  28/1300/2000/8192/60000 байт (включая IP fragmentation), DNS UDP и TCP с LAN;
- C++ transparent-проба: TLS 1.2 и TLS 1.3-HRR, по 1 MiB echo на сеанс,
  проверка сертификата, hostname, содержимого и штатного закрытия.

После каждой пары проверяется DNS UDP/TCP с gateway. Данные создаются и
проверяются только C++; Node запускает процессы и читает bounded verdicts и
счётчики. В отличие от предыдущего loopback soak, здесь production engines
используют реальные TUN: нет `--test-packet-fd` и payload через Node.

Обе engine-роли должны оставаться теми же процессами. Сэмплы `/proc` примерно
раз в 500 мс проверяют process starttime, RSS, FD и threads. После нагрузки
FD/threads не должны превышать baseline. Лимиты: RSS <128 MiB, рост относительно
baseline <64 MiB, максимум baseline+64 FD и baseline+32 threads. CPU сохраняется
в raw ticks, не интерпретируется как WAN throughput. Сэмплирование может пропустить
короткие пики; RSS не PSS, эти границы не доказывают отсутствие всех утечек.

Затем обе роли останавливаются SIGTERM. Отчёт требует успешного выхода,
единственного `ready` у boring-ветки, generation 0, положительных TX/RX и
0 dropped packets за время жизни этих engine до инъекции fault. TX одной роли
должен совпадать с RX другой. Проверяется рост kernel TUN packet counters.
Без изменения guards обе роли запускаются
заново и повторно проходят TCP/UDP/DNS и TLS-пробы.

Сохраняются исходные network gates: положительный прямой контроль до guard,
HTTPS не идёт через TUN, SNAT/MASQUERADE, policy/no-downgrade, SIGKILL обеих
ролей, удаление client split routes в crash-окне, восстановление и selected-origin
capture. Ненулевой direct traffic после guard или kernel capture drop запрещает
успешный итог. Итого — 14 gates; отсутствие блока нагрузки не может превратить
load-режим в успешный короткий network smoke.

## Границы

Это real-TUN sustained functional/resource test, **не benchmark**: 1 vCPU TCG,
stop-and-wait echo, искусственно медленный TLS origin, небольшие интервалы
между раундами. Из этих байтов/секунд нельзя выводить скорость интернета или
предельную пропускную способность native. Один boring peer; нет нескольких
одновременных TLS users, долгоживущего TLS-сеанса или многочасового soak.

Сеть и default routes статические; installer/systemd/reboot проверяются отдельным
combo boot стендом. Capture покрывает выбранный IPv4 origin, не all-egress,
IPv6 или ранний boot. Это не физическая ARM64/Radxa/VPS-приёмка.
