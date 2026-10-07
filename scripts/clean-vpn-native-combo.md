# Native combo: общий exit-порт и две C++ ветки

Native combo checkpoints, 2026-10-07: engine, единый network profile и fresh
installer/systemd реализованы. [Двухзагрузочная приёмка](clean-vpn-native-combo-boot.md)
прошла 23/23 gates с реальными TUN/DNS, crash/restart обеих ролей и durable replay.
Ниже сохранены отдельные engine/network результаты с их собственными границами.

Результат: **390/390** native/routes regression, CTest **6/6** normal и **6/6**
ASAN/UBSAN, combo/transparent integration **7/7** с ASAN/UBSAN. Hashes и scope:
[fixtures/clean-vpn-native-combo-report.json](fixtures/clean-vpn-native-combo-report.json).
Трёхминутный boring native soak также прошёл без потерь/reconnect; это отдельная
регрессия базового тракта, не combo endurance и не benchmark.

В одном C++ процессе client работают boring-tls TUN reactor и transparent
SO_ORIGINAL_DST listener. Exit принимает обе ветки одним TCP listener:

| Входящий ClientHello | Ветка |
| --- | --- |
| SNI точно равен `public_name` (без учёта регистра) | BoringSSL TLS 1.3 → HTTP/2 → authenticated TUN |
| SNI — поддомен `public_name` | Native enc-SNI authorization → durable replay admission → transparent relay |
| Другое имя, malformed TLS, timeout | Закрыть соединение |

Выбор ветки не заменяет аутентификацию. Неверный ключ, испорченный token,
запрещённый destination и replay **никогда не переключаются** в boring-ветку.
Прямого fallback к origin на клиенте нет. Non-TLS на перехваченном порту
закрывается, а не пытается выйти напрямую или повторить уже начатый поток.

## Владение данными и ограничения

`combo.hpp` делает bounded `MSG_PEEK`: полный ClientHello остаётся в сокете
вместе с coalesced tail. Дескриптор передаётся внутри того же процесса либо
boring reactor, либо существующему native relay. Внутреннего TCP proxy, передачи
FD/payload в Node и дополнительного внешнего listener для boring нет.

- ClientHello: существующий лимит 64 KiB, deadline 5 секунд.
- Не более 16 pending peeks, 16 relay workers, 32 jobs всего.
- Очередь boring descriptors — 16; admission — 32 соединения/секунду.
- Boring reactor сохраняет собственные лимиты TLS/auth sessions и peer isolation.
- Slow/incomplete hello не блокирует обработку других принятых соединений.
- Частичный peek не создаёт busy-loop по постоянно readable сокету.
- Ошибка acceptor прекращает весь engine, чтобы не оставлять частично рабочий
  combo. Обычная ошибка отдельного потока закрывает только этот поток.
- Replay journal обязателен для exit; автоматического reset/init нет.

Сетевые guards, маршруты, TUN и REDIRECT остаются обязанностью внешнего control
plane. Для combo теперь есть единый профиль, описанный ниже; нельзя смешивать
standalone network profiles: у них разная политика FORWARD/OUTPUT.
Fresh installer принимает combo только с привязанным `--site-profile`;
публикует disabled bundle, без автоматического enable/start.

## Конфигурация

Строгая верхняя схема: ровно `version: 1`, `transport: "combo-tls"`, `role`,
`boring` и `transparent`. Вложенные объекты — существующие полные конфигурации
соответствующих engine-режимов; в `boring` поля `transport` нет.

- Обе вложенные роли совпадают с верхней.
- Boring endpoint равен transparent exit endpoint (client) или listener (exit).
- Boring client SNI равен transparent `public_name`; имя проверки сертификата
  остаётся отдельным `server_name`, CA/hostname verification не отключается.
- Transparent PSK должен отличаться по **байтам** от каждого boring peer PSK.
- `--check-config` проверяет обе ветки без создания replay state или listener.
- Явный `--init-transparent-replay CONFIG` понимает combo exit, но не client.
- Runtime требует `--config CONFIG --service`; stdin packet/control bridge нет.

Capabilities помечают combo экспериментальным и явно сообщают
`site_provisioning: true`. Это поддержка связанного fresh site bundle,
не hot-switch/profile UI и не обновление существующей установки.

## Лаборатория

```bash
cmake --build native/clean_vpn/build --target \
  clean-vpn-engine clean-vpn-engine-fixture transparent-socket-test combo-test -j2
ctest --test-dir native/clean_vpn/build --output-on-failure
node --test scripts/test-native-combo.mjs scripts/test-native-transparent.mjs
```

Для ASAN/UBSAN используется уже подготовленная `CVPN_SANITIZE=ON` сборка и
`CVPN_BUILD=native/clean_vpn/build-asan` перед `node --test`.

Component test проверяет fragmented peek/coalesced tail, ветвление, отказ
replay/wrong-key/tampered token без TLS downgrade или origin connect, pending
admission cap, отсутствие head-of-line blocking и bounded stop.

Engine test выполняется в новом пустом user/network namespace. C++ до сетевых
команд проверяет namespace identity и единственный интерфейс `lo`; fallback
в сеть хоста нет. Два настоящих engine-процесса получают test-only packet FD
вместо TUN. Пакеты генерирует и сравнивает C++ fixture, Node получает только
результаты. Production binary не поддерживает этот FD.

На одном exit-порту одновременно проверяются **204 IPv4 пакета** и TLS 1.2/
TLS 1.3-HRR echo через настоящий REDIRECT. SIGKILL exit не приводит к прямому
relay fallback; после restart старый token запрещён, свежий TLS и пакеты работают.
Сохраняются исходные standalone transparent проверки.

Ограничения этого первого engine-теста: scoped loopback origin, fixture packet FD, один boring peer,
без реального combo TUN/DNS/SNAT/MSS, независимого leak-capture, systemd combo
boot, физических устройств и WAN benchmark. ECH/0-RTT, key rotation и браузерные
профили не объявляются готовыми.

## Единый network profile и реальный TUN

`nativeNetworkPlan()` принимает строгий flat профиль boring с дополнительными
`transport: "combo-tls"`, `listen_port` и `deny_ipv4`. Client требует LAN;
exit требует `lan: null` и `listen_port === port`. На client порты relay, DNS и USB rescue
не могут конфликтовать. Это профиль выделенного хоста/namespace, не способ
добавить правила поверх существующего firewall.

- LAN TCP/443 к разрешённым public IPv4 перехватывается через REDIRECT.
  Запрещённые, private/local/control назначения на TCP/443 не уходят в boring.
  Non-TLS или неподдержанный ClientHello закрывается, без повторной попытки
  через другой транспорт и без прямого fallback.
- Остальной поддержанный IPv4 с LAN идёт через boring TUN, SNAT и MSS.
  UDP/443 тоже относится к boring, а не к transparent TCP relay.
- Plain DNS с LAN и самого gateway перехватывается **до** исключений HTTPS,
  обрабатывается C++ DNS relay и передаётся через TUN. Mark native upstream
  предотвращает рекурсивный DNS-перехват.
- HTTPS самого gateway пока идёт через boring: OUTPUT HTTPS REDIRECT не включён.
  `deny_ipv4` — политика transparent HTTPS, не глобальная geo/ACL для всех IP.
- Exit принимает обе ветки одним портом. Relay OUTPUT ограничен public HTTPS;
  packet FORWARD/MASQUERADE ограничен TUN-подсетью. IPv6 остаётся default-DROP.
- Единый journal владеет filter/NAT/mangle/TUN. Повторный запуск только проверяет
  состояние; другой профиль, foreign rules и частичная установка не принимаются.

Запуск отдельной лаборатории (проверенный base image и QEMU tools обязательны):

```bash
cmake --build native/clean_vpn/build --target clean-vpn-engine socket-test transparent-socket-test -j2
node scripts/clean-vpn-native-lab.mjs "$CVPN_LAB_BASE" "$CVPN_QEMU_TOOLS" --native-combo-network
```

NIC-less QEMU содержит пять network namespaces: LAN app, gateway, exit, origin
и соединяющий их виртуальный сегмент. В client и exit используется production
C++ engine с настоящими TUN. Node не создаёт/не читает пакеты: TLS, TCP/UDP,
DNS и packet capture выполняют C++ fixtures; наружу выходят только verdicts.

12 gates проверяют положительный прямой контроль до установки guard, создание
TUN, отсутствие HTTPS в счётчиках TUN, одновременные TLS 1.2/TLS 1.3-HRR и
TCP/UDP, host/LAN DNS, двойной NAT, policy/no-downgrade, SIGKILL client с удалением
split routes, SIGKILL exit и восстановление обеих ролей. Origin capture проверяет
выбранный IPv4-трафик к `1.1.1.1`: он должен приходить от exit, не от gateway/LAN.
При потерях capture в ядре итог не принимается.

Результат: [fixtures/clean-vpn-native-combo-network-report.json](fixtures/clean-vpn-native-combo-network-report.json).
VM **12/12**; regression **403/403**; CTest normal/ASAN **6/6** в каждой сборке;
combo/transparent ASAN integration **7/7**. Capture: 426 пакетов положительного
контроля, 0 прямых пакетов после guard, 0 потерь capture в ядре.
Это runtime при статических fixture-маршрутах, один boring peer и выбранный IPv4
origin; не all-egress/IPv6 capture, не systemd/reboot combo, не физическая приёмка
и не benchmark. Fresh installer binding, route coordinator и systemd crash/reboot
обеих combo-ролей теперь проверены [отдельным стендом](clean-vpn-native-combo-boot.md):
23/23 gates, 416/416 regression, CTest normal/ASAN 6/6, ASAN integration 16/16.
Дополнительно пройден [180-секундный native mixed-load](clean-vpn-native-combo-soak.md)
с проверкой пакетов/TLS и ресурсов обоих процессов. Это loopback/fixture-FD
проверка, не замер пропускной способности.
Добавлена [длительная real-TUN нагрузка](clean-vpn-native-combo-load.md): production
engine client/exit, параллельные TLS и TCP/UDP, DNS с LAN/gateway, ресурсы,
точные встречные TX/RX, штатный перезапуск и прежние crash/capture gates.
Далее — воспроизводимые native-only измерения, без вывода о WAN-скорости по
результатам эмулятора.
