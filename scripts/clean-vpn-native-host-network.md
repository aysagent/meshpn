# Самостоятельный native lifecycle на существующем хосте

Checkpoint 2026-10-29. Новый `--host-profile` устанавливает выключенный сетевой
owner для проверенного Radxa IPv4-профиля. Старый Node.js VPN не запускается,
не анализируется и не восстанавливается. Node остаётся только control plane;
TUN payload, TLS и DNS обслуживает C++ engine.

## Ограниченный контракт

- boring-tls client, `tun0`, `10.99.0.2/32`, MTU 1400, native DNS включён;
- uplink `wlan0` с единственным IPv4 default gateway;
- USB `usb0`, `192.168.7.1/24`, уже настроенный forwarding=1;
- независимый активный cvks4 guard both/block с тем же exit и SSH port 22;
- старые VPN/TUN и USB SNAT owner заранее остановлены; существующий TUN не принимается;
- guard, USB rescue, dnsmasq, resolver-файлы, Wi-Fi и чужие службы не перенастраиваются;
- нет конкурирующего администратора собственных маршрутов/DNS/NAT;
- этот профиль не является универсальным установщиком Linux или exit.

Пример приватного host profile (не команда автоматического применения на плате):

```json
{"version":1,"guard_unit":"clean-vpn-killswitch.service","guard_script":"/usr/local/bin/clean-vpn-killswitch.sh"}
```

Передать установщику `--host-profile=/absolute/host.json` вместо внешнего
`--network-unit/--guard-unit` или dedicated `--site-profile`. Engine config,
CA/PSK и опциональный clock-profile передаются обычным способом.
Установщик публикует файлы, но ничего не запускает и не включает.
После проверки активируется `native-NAME-network.service`, а не engine напрямую.
Сам C++ остаётся отдельным systemd MainPID `native-NAME.service`.

## Владение и восстановление

Сетевой owner удерживает namespace lock и журнал в `/run`. TUN создаётся
непостоянным, получает уникальный alias и только затем становится persistent.
Прерывание до persistence удаляет TUN вместе с FD; после persistence восстановление
проверяет alias, а после фиксации identity — также ifindex. Подмена означает отказ.

Существующие host-route/DNS journals сохраняют intent перед изменением и удаляют
только собственные операции. USB SNAT и два MSS-правила имеют отдельный случайный
owner tag. Нет flush или восстановления снимка чужой таблицы.
DNS перенаправляется в native listener; его временная недоступность не разрешает
прямой upstream. Файлы системного DNS и конфигурация dnsmasq не меняются.

Engine зависит через BindsTo/After от owner и guard. `ExecStopPost` отдельно
восстанавливает сеть после штатного stop или SIGKILL owner, проверяя остановку
engine. Guard не снимается. SIGKILL engine допускает его обычный systemd restart
без пересоздания сети. Сбой owner запускает recovery перед новой попыткой.
Журнал `/run` same-boot; это не сохранение kernel state между загрузками.

## Проверки на этом checkpoint

- 18 проверок в настоящем ARM64 Linux netns: TUN/DNS/routes/NAT, повторный запуск,
  intent cut-points, чужой alias, active engine, guard failure, точный возврат
  исходных настроек и сохранение sentinel. Systemd-состояние в этой матрице injected.
- 10 сценариев в отдельном systemd-контейнере без внешней сети: настоящие native
  client/exit, USB HTTPS, UDP/TCP DNS, engine SIGKILL, owner SIGKILL/ExecStopPost,
  stop/restart, отказ/возврат exit, отсутствие direct fallback.
- 23 Linux-регрессии установщика boring/transparent/combo/clock/host — PASS.
- На Mac базовый installer test использует `/tmp` и отказал на symlink_destination;
  тот же тест пройден на Linux. Kernel netns-тест через amd64 эмуляцию не получил
  поддержку iptables; успешная матрица выполнена на native ARM64.

Физические узлы этой реализацией пока не изменены. Это не boot/power-loss
приёмка, не полный leak/soak/performance тест и не заявленная ежедневная установка.
Следующий gate — интеграция boot/clock/updater, затем ограниченная физическая проверка.

Воспроизведение kernel matrix: `CVPN_DISPOSABLE_HOST_NET=1 node
scripts/test-native-host-network-linux.mjs` только в отдельном пустом netns.
Systemd fixture: `CVPN_DISPOSABLE_HOST_SYSTEMD=1 node
scripts/lib/native-host-systemd-lab.mjs` только в одноразовом NIC-less Linux
systemd окружении, с кодом в `/project` и engine в `/usr/local/bin`.
