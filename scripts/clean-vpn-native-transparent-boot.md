# Native transparent: installer и две загрузки systemd

Отдельный стенд для `transparent-tls`, не продолжение boring-tls/TUN теста.
Запускается только в disposable QEMU без NIC, shared filesystem и доступа к
Radxa/VPS. Внутри VM — systemd PID 1, приложение, gateway, exit и TLS origin
в отдельных namespace; пятый namespace содержит синтетический WAN bridge.

Checkpoint 2026-10-07: **19/19 gates прошли на двух загрузках**, отчёт с hashes
и boot IDs — [fixtures/clean-vpn-native-transparent-boot-report.json](fixtures/clean-vpn-native-transparent-boot-report.json).
Регрессия 173/173; CTest 5/5 normal и 5/5 ASAN/UBSAN. Исходный VM отчёт:
`/var/tmp/meshpn-native-lab-XKVUac/report.json`.
Общий site renderer дополнительно проверен boring-tls VM: **17/17 gates** на
двух загрузках, `/var/tmp/meshpn-native-lab-rvHSAf/report.json`.

```bash
node --test scripts/test-native-transparent-boot.mjs \
  scripts/test-native-transparent-install.mjs scripts/test-native-network-profile.mjs

node scripts/clean-vpn-native-lab.mjs \
  /absolute/path/to/verified-host-boot-base \
  /absolute/path/to/qemu-tools-root --native-transparent-boot
```

Аргументы — подготовленные kernel/initramfs и QEMU tools из существующей VM
лаборатории, не каталоги физических client/exit. Runner проверяет отчёт базы и
hash kernel, создаёт собственный temporary каталог и ext4-диск. Не запускать
внутренний `native-transparent-boot-vm.mjs` вручную на целевом сервере: он
отказывает вне маркированной VM. Это не команда установки production VPN.

## Критерии

Первая загрузка — 11 gates:

- Настоящий fresh installer публикует disabled bundle для обеих ролей.
- Guard устанавливается до поднятия uplink; activation target ждёт engine.
- systemd напрямую запускает C++ engine, Type=notify; `/proc/PID/exe` проверен.
- TLS 1.2 и TLS 1.3 с HRR через LAN REDIRECT и оба engine.
- Выбранные DNS/UDP/non-HTTPS/direct-listener probes заблокированы.
- SIGKILL каждой роли с обычным `Restart=on-failure`, затем свежий TLS.
- Отдельные crash-окна с временным `Restart=no`: нет прямого обхода,
  после восстановления политики снова работает TLS.
- Stop обоих targets сохраняет default-DROP; приложение не выходит напрямую.
- Установленные bundle/units и непустой replay journal сохраняются на ext4.

Вторая загрузка — ещё 8 gates:

- Другой boot ID; точное совпадение inventory файлов, каталогов, прав и hashes,
  включая байты replay journal до старта сервисов.
- Автозапуск enabled targets с guard-before-uplink и прямыми C++ engine.
- TLS и выбранные негативные probes после reboot.
- Exit отказывает при удалённом и повреждённом replay state, ничего не
  инициализирует/переписывает; живой gateway не обходит отказавший exit.
- Только явное восстановление сохранённых fixture-байтов возвращает TLS.
- Stop targets снова сохраняет блокировку.

Fixture link owner предоставляет адреса/маршруты, не обрабатывает пакеты.
Node driver выполняет provisioning, systemd-команды и проверяет metadata.
TLS, ClientHello, relay и application bytes остаются в C++ fixture/engine.

Копирование установленного дерева между initramfs и тестовым диском — механизм
стенда, **не** production restore/adoption. Он сохраняет directory modes:
replay leaf должен оставаться `0700`, journal/lock — `0600`. Проверка этих прав
в engine не отключается. Для fault-сценариев driver временно меняет только
fixture drop-in и возвращает исходный Restart перед сохранением установки.

## Границы доказательства

Это controlled reboot, не внезапное отключение питания. Проверяется перенос
точных replay-байтов и их чтение новым процессом, не повтор live auth-token
через reboot за пределами его временного окна. Нет независимого раннего boot
capture, DHCP/network-manager интеграции, all-egress/IPv6 leak acceptance,
физического ARM64 boot, key rotation или обновления существующей установки.
Нет измерения скорости Интернета. ECH/0-RTT, browser-profile fidelity и native
combo этим стендом не объявляются реализованными.
