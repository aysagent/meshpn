# Прямой native service: лабораторный этап

2026-10-07. Следующий шаг после multi-peer exit. Это **не** готовый установщик
на Radxa/VPS и не повод заменять работающие units вручную.

## Процесс и границы ответственности

`clean-vpn-engine --config /absolute/config.json --service` запускает C++ engine
напрямую. В этом явном режиме stdin не читается, EOF не означает stop;
SIGINT/SIGTERM завершают работу. Прежний режим `--config` сохраняет bounded
control pipe и завершение при его EOF для существующих контроллеров/тестов.

При заданном `NOTIFY_SOCKET` engine сообщает systemd состояние через UNIX
datagram socket (filesystem/abstract), без libsystemd и без передачи descriptors
или payload. Exit отправляет `READY=1` после открытия TUN и listener, client —
после первого успешного TLS/H2 authenticated session; DNS listener, если включён,
создаётся до этого. Это **готовность сервиса**, не постоянная гарантия egress:
при потере соединения unit остаётся active, а `STATUS` показывает состояние.
`READY=1` отправляется один раз. Неверный/недоступный notify endpoint не должен
давать ложную готовность; служба завершается с ошибкой. Без `NOTIFY_SOCKET`
режим работает как foreground daemon.

Формат следует [контракту systemd sd_notify](https://github.com/systemd/systemd/blob/main/man/sd_notify.xml).

`lib/native-service-unit.mjs` — чистый renderer, **не** installer. Он принимает
абсолютные пути binary/config и имена отдельно управляемых network/guard units.
Нет shell interpolation, systemd specifiers или исполняемого config payload.
Созданный unit использует:

- direct C++ `ExecStart`, `Type=notify`, `NotifyAccess=main`, stdin=null;
- `--check-config` перед запуском, on-failure restart с лимитом частоты;
- `Requires` + `After` + `BindsTo` для network/guard;
- ограниченные stop/start deadlines, memory/tasks/FD, capability set;
- read-only filesystem, no-new-privileges и доступ к `/dev/net/tun`;
- **никакого** ExecStop, снимающего guard, routes, DNS или удаляющего TUN.

TUN, адреса, маршруты, DNS interception, SNAT и firewall по-прежнему готовит
внешний control plane. Persistent TUN/защита не удаляются при crash/restart
engine. Прямой daemon пока не включает route ownership/DHCP watcher из USB
контроллера: лаборатория проверяет socket reconnect при возврате статического
uplink, не смену gateway/IP. Нельзя просто переносить этот unit в действующую
USB-схему и считать provisioning готовым.

## Проверки

- C++ notify test: filesystem/abstract sockets, единственная readiness,
  остановка, отклонение инъекции metadata.
- C++ integration fixture: оба service-процесса игнорируют stdin/EOF,
  передают 100 проверенных пакетов и штатно завершаются по SIGTERM.
- JS тестирует renderer/config injection; пакеты не проходят через JS.
- `clean-vpn-native-lab.mjs HOST_BOOT_BASE QEMU_TOOLS_ROOT --native-systemd`:
  настоящий systemd PID1 в NIC-less VM; два клиента в разных netns/TUN и
  общий exit с двумя независимыми ключами; все три MainPID — native binary.
  Трафик генерируется/проверяется C++ socket fixture.

VM gates: direct positive control; engine не запускается при отказе guard;
client остаётся activating до успешной аутентификации; оба peer и оба DNS stub;
изолированная остановка клиента; restart; SIGKILL client и exit с автоматическим
restart; обрыв/возврат uplink одного клиента; остановка guard останавливает
зависимые engines; после удаления TUN routes прямой fallback остаётся заблокирован;
завершение процессов.

Ограничения: один boot, fixture network/guard, не production installer; нет
проверки отсутствия раннего boot leak. Positive control намеренно работает
до установки guard. Проверка неверного guard означает запрет запуска engine,
не защиту всей машины от неисправного firewall. Multi-peer проверен на двух
настоящих kernel TUN, 32-peer saturation — отдельно на C++ socket fixture.
VM не имеет внешней сети, скорость интернета не измеряется.

## Результат 2026-10-07

Повторный native-systemd прогон: **12/12 gates**, `status=passed`.
Локальный полный отчёт: `/var/tmp/meshpn-native-lab-lf6gLk/report.json`;
предыдущий успешный прогон: `/var/tmp/meshpn-native-lab-ZSR8ws/report.json`.
SHA-256 production engine:
`e8848c3305779d4e81282281ce409c4033eaa8ad77fdb39f2f57723eea05df51`.
Общий regression-набор: **383/383**; CTest **3/3**; ASAN/UBSAN CTest **3/3**
и integration-набор **18/18**. Сторонние зависимости не инструментированы.
Первая попытка лаборатории (`XdfwGr`) выявила ошибку fixture: `reset-failed`
обращался к уже выгруженному unit. Исправлено; этот прогон не считается успешным.

Следующее: безопасный native-only installer/provisioning, boot/reboot и
route ownership/uplink tracking. После них — transparent/combo. Ничего на
пользовательских Radxa/VPS не разворачивалось.
