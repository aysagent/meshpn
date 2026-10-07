# Native combo: directional benchmark в изолированной лаборатории

Режим `--native-combo-benchmark` проверяет методику измерений на полностью native
client/exit. **Результаты TCG не являются скоростью Интернета или пределом
производительности Radxa/VPS.** Legacy client/exit и Node packet path не используются.

Проверено 2026-10-07: два полных VM-прогона, **13/13 gates** каждый, по 18 образцов:
48 MiB upload, 48 MiB download и 600 измеряемых RTT. Все payload проверены,
TUN counters подтверждают выбор ветки. В последнем прогоне selected-origin
capture: 416 direct packets до guard (положительный контроль), 0 после,
0 kernel capture drops. [Сырые результаты обоих прогонов и hashes](fixtures/clean-vpn-native-combo-benchmark-report.json).
Регрессия 434/434, normal и ASAN/UBSAN CTest 7/7 в каждой сборке,
ASAN integration 12/12, targeted benchmark/network/load 18/18.
Production engine не изменён этим checkpoint.

```bash
cmake -S native/clean_vpn -B native/clean_vpn/build
cmake --build native/clean_vpn/build -j2
ctest --test-dir native/clean_vpn/build --output-on-failure
node scripts/clean-vpn-native-lab.mjs \
  /absolute/path/to/verified-host-boot-base \
  /absolute/path/to/qemu-tools-root --native-combo-benchmark
```

Нужны существующий проверенный base image и QEMU tools; это не команда запуска
на Radxa. VM: NIC-less, 1 vCPU TCG, 1536 MiB, без host shared filesystem.
Сеть хоста, физические устройства и внешние VPS не меняются. Драйвер отказывает
вне QEMU с нужными markers. C++ workload также требует отдельный namespace и
ожидаемый набор интерфейсов. `--self-test` использует только AF_UNIX socketpair.

## Что измеряется

Три повтора по порядку: boring upload/download/latency, затем transparent
upload/download/latency. Итого 18 образцов, один TCP stream на образец.

- Boring: приложение LAN → gateway TUN → native boring-tls client/exit →
  plaintext TCP origin на синтетическом `1.1.1.1:4445`. Счётчик TUN обязан расти.
- Transparent: приложение LAN → kernel REDIRECT → native transparent client/exit →
  TLS origin `1.1.1.1:443`. TLS 1.3, проверка CA/hostname `localhost` и clean
  close-notify. Счётчик TUN не должен расти.
- Upload: 8 MiB потоком, origin проверяет каждый байт и возвращает подтверждение.
- Download: origin отправляет 8 MiB потоком; приложение проверяет каждый байт,
  получает completion marker и отправляет подтверждение. Нет per-block echo/ACK.
- Latency: 5 прогревочных и 100 измеряемых 32-байтных echo RTT на установленном
  соединении, median и nearest-rank p95. Это application RTT, не ICMP ping и не
  задержка установления нового TLS-соединения.

Тестовые данные генерируются и проверяются C++, с bounded 64 KiB buffers,
socket timeouts и 120-секундным deadline каждого образца. В TLS benchmark-пути нет
искусственной паузы slow-consumer, используемой старой echo-пробой. Node читает
только отчёт и `/proc` metadata, не payload. Ошибка/частичный transfer не становится
успешным образцом; автоматических повторов неудачных образцов нет.

Goodput: `payloadBytes * 8 / seconds / 1e6` — decimal Mbps, не MiB/s и не сумма
обоих направлений. Таймер C++ стартует после connect/TLS и получения готовности
origin; включает start marker, передачу, проверку и completion acknowledgment.
Для download не ожидается дополнительный ответ на финальное подтверждение.
Handshake не входит в goodput, но входит в более широкое CPU-окно.

CPU отдельно для production engine client и exit: разность process-wide
`utime+stime` из `/proc/PID/stat`, перевод в секунды по `_SC_CLK_TCK` гостя,
процент одного ядра за wall time всего процесса-пробы, включая connect/TLS/close.
Проверяется неизменность PID starttime. Не включены CPU приложения, origin,
Node controller и kernel вне этих процессов. RSS сэмплируется примерно каждые
100 мс; это не PSS, короткие пики могут быть пропущены. Окна CPU и goodput
различаются и явно подписаны в JSON; их нельзя выдавать за один интервал.

## Приёмочные ограничения

Benchmark добавляет один gate к исходным 12 network gates. Сохранены DNS/SNAT,
policy/no-downgrade, SIGKILL client/exit, удаление client routes в crash-окне,
restart и независимый selected-origin capture. Нужен положительный direct
контроль до guard, 0 direct packets после guard и 0 kernel capture drops.

Это обе ветки combo, не сравнение со standalone-конфигурациями и не доказательство
максимальной пропускной способности: короткие single-stream transfers, общий
эмулируемый CPU для всех узлов, фиксированная очерёдность, локальные origins,
MTU 1400. Нет WAN, физического ARM64, многочасовой нагрузки, all-egress capture,
ECH/0-RTT, нескольких одновременно нагруженных пользователей или браузерных
профилей. Порогов «достаточно быстро» нет: этот checkpoint проверяет корректность
измерений и сохраняет сырые результаты, не обещает ускорение Интернета.

Следующая отдельная задача — воспроизводимый native-only прогон на реальном
железе/между VPS с явными параметрами сети и CPU, затем WAN Speedtest. Физические
узлы данным лабораторным режимом не затрагиваются.
