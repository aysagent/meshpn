# Native combo: общий exit-порт и две C++ ветки

Первый engine checkpoint, 2026-10-07. Это **не готовый combo site deployment**:
общий network profile/installer и VM с реальными TUN/DNS ещё впереди.

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
plane. Этот checkpoint не даёт разрешения смешивать standalone network profiles:
у них разная политика FORWARD/OUTPUT. Production installer пока отвергает combo.

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
`site_provisioning: false`. Это не поддержка hot-switch/profile UI.

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

Ограничения: scoped loopback origin, fixture packet FD, один boring peer,
без реального combo TUN/DNS/SNAT/MSS, независимого leak-capture, systemd combo
boot, физических устройств и WAN benchmark. ECH/0-RTT, key rotation и браузерные
профили не объявляются готовыми.

Следующая точка: единый combo network profile и namespace/VM приёмка с LAN,
реальными TUN, DNS/UDP через boring, HTTPS через transparent, default-DROP при
отказах. После этого — fresh installer и systemd crash/reboot обеих ролей.
