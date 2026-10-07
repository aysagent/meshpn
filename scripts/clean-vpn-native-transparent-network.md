# Native transparent: standalone network guard (laboratory checkpoint)

Сетевые правила и kernel REDIRECT обслуживаются control plane; ClientHello,
TLS, TCP relay и тестовые payload обрабатываются только C++. Это **не** готовая
установка на Radxa/VPS: fresh site installer уже собирает transparent bundle,
но его отдельная systemd/boot приёмка ещё не завершена. Нельзя применять его к
действующему USB/TUN firewall.

## Контракт

Dedicated IPv4 gateway принимает **только LAN/USB TCP 443**. Host OUTPUT не
перехватывается. DNS (TCP/UDP 53), QUIC/остальной UDP, HTTP/non-443 и IPv6 не
получают прямого fallback. Приложение пока должно знать адрес HTTPS origin;
защищённый DNS/остальной трафик будут подключены отдельным native путём в combo.
DHCPv4 uplink и SSH 2222 из выбранной LAN — явные служебные исключения. Loopback
остаётся локальным; это не изоляция от привилегированного администратора.

Пример **network profile**, не engine config:

```json
{
  "version": 1,
  "transport": "transparent-tls",
  "role": "client",
  "uplink": "wan0",
  "endpoint": "154.62.226.216",
  "port": 443,
  "listen_port": 33002,
  "lan": { "interface": "lan0", "subnet": "192.168.7.0/24" },
  "deny_ipv4": []
}
```

- Client: REDIRECT в PREROUTING только для указанной LAN/subnet и TCP 443;
  INPUT listener разрешён только для DNAT connection. Прямое подключение к
  listener из LAN не разрешается. Engine client слушает `0.0.0.0:listen_port`.
  OUTPUT uplink — только заданный exit TCP endpoint и DHCP.
- Exit: `role=exit`, `lan=null`, `listen_port=port`, endpoint — собственный
  uplink IPv4. INPUT разрешает native listener и ответы HTTPS; OUTPUT — ответы
  на принятые подключения (conntrack reply direction) и public TCP 443.
  Private/special/admin-deny назначения блокируются до разрешения origin TCP.
- Обе стороны: INPUT/FORWARD/OUTPUT по умолчанию DROP; IPv6 вне loopback DROP.
  TUN, SNAT и forwarding не создаются/не включаются.
- Special-purpose IPv4 диапазоны согласованы с C++ `public-https` policy.
  C++ дополнительно заново проверяет локальные адреса/подсети перед connect.
  Engine должен использовать `destination_policy.mode=public-https` и тот же
  `deny_ipv4`; локально невидимые management/NAT адреса задаются администратором.
  Installer требует точного совпадения destination policy, endpoint и listener
  между engine config и network profile; несовпадение отвергается до записи.

Используется общий `applyNativeNetworkProfile`: только пустые dedicated tables,
выбранные links DOWN, forwarding=0; pre-test правил, сначала IPv6/IPv4 DROP,
readback, journal stages и привязка к boot/network/user namespace. У transparent
в journal поле `tun=null` (унаследованное имя стадии `tun` не создаёт интерфейс).
Повторный запуск только сверяет правила/интерфейсы; partial install, чужие
правила, другая конфигурация или namespace требуют review без очистки/перезаписи.
Stop/SIGKILL engine не снимает firewall и REDIRECT. Concurrent network/firewall
administrators не поддерживаются. Адреса/default/DHCP — внешний владелец.

## Fresh installer / systemd bundle

`installNative` принимает transparent только с `siteProfile`: произвольные
external network/guard dependencies без связанного профиля не принимаются.
Engine должен объявлять поддержку public-https, SO_ORIGINAL_DST и durable replay.
Исходный engine config проверяется самим C++ engine, затем planner связывает его
с firewall. Client listen — строго `0.0.0.0:listen_port`, exit listen — endpoint:port.
Explicit destination allowlist вместо `public-https` для этого site не допускается.

Bundle содержит четыре unit: guard → link gate → direct C++ engine и общий
activation target. TUN route coordinator, DNS interceptor и сертификаты TLS
termination в transparent bundle отсутствуют. Payload остаётся opaque для relay.
Client/exit service использует Type=notify, Restart=on-failure и BindsTo guard/gate.
У engine нет CAP_NET_ADMIN/CAP_NET_RAW и доступа к `/dev/net/tun`.
Namespace TLS/crash-прогон также запускает оба engine с capability bounding set
только CAP_NET_BIND_SERVICE и no-new-privs: SO_ORIGINAL_DST проверен без ADMIN.

Для exit installer переносит PSK и переписывает replay path в приватный каталог
`/opt/clean-vpn-native/<name>/replay` (0700), затем **до публикации unit** вызывает
скопированный engine с `--init-transparent-replay`. Временный owner-only config
инициализации удаляется после успешной записи. Replay journal/lock — 0600.
Manifest отмечает replay как mutable state; systemd разрешает запись только в
этот каталог через ReadWritePaths, остальной bundle защищён ProtectSystem=strict.
Unit не имеет автоматической инициализации или сброса replay при старте.

Это только fresh install, не миграция/ротация: исходный replay path должен ещё
не существовать. Существующие журналы не копируются и не сбрасываются. Для
разных exit instances нужен отдельный PSK; повторное использование ключа с
независимым новым журналом не даёт общей replay-защиты. Безопасная ротация и
восстановление журнала из backup остаются отдельной задачей.

Dry-run ничего не создаёт. Interrupted install оставляет inspectable bundle,
повторный запуск отказывает без adoption/cleanup/reinitialization. Installer
не выполняет daemon-reload, enable/start и не меняет сеть.

## Проверка

```bash
node --test scripts/test-native-network-profile.mjs scripts/test-native-transparent.mjs
```

Новый `native-transparent-network-lab.mjs` создаёт пять изолированных network
namespace: WAN bridge, приложение, gateway, exit, TLS origin. До сетевых команд
проверяются смена namespace и единственный исходный интерфейс lo; недоступный
unshare/netfilter — ошибка, не разрешение работать в namespace хоста.
Ни физической сети, ни доступа к настоящему 1.1.1.1 нет.

Проверены реальные PREROUTING REDIRECT/SO_ORIGINAL_DST, client и exit как два
обычных C++ engine, TLS 1.2/1.3-HRR, запрет selected non-HTTPS/direct-listener
probes, SIGKILL client и exit по отдельности, свежие TLS после обоих restart.
Capture на synthetic origin получает positive-control UDP 53/443 до guard;
после установки guard новые UDP probes туда не доходят. TLS origin принимает
ровно шесть ожидаемых соединений. Общий firewall journal проходит аудит после
падений/восстановления без удаления правил.

Лаборатория использует общий apply-код с in-memory journal adapter, не root CLI
с дисковым journal. Это не проверка systemd boot, fsync journal при потере
питания, физического uplink, полного IPv6/DNS leak acceptance или скорости.
Отдельная [VM systemd/cold-boot/crash приёмка](clean-vpn-native-transparent-boot.md)
добавлена следующим checkpoint ниже; она не расширяет scope этого namespace-теста.

Checkpoint 2026-10-07: общий native regression-набор **159/159**, без skip;
CTest **5/5** normal и ASAN/UBSAN; все четыре transparent-прогона (codec/TCP,
scoped engine, public-policy и новый network guard) прошли normal и ASAN/UBSAN.
Повторного VM boot-прогона в этом checkpoint не было. Radxa/VPS/Mac не менялись.

Следующий installer checkpoint добавляет проверки binding, owner-only relocation,
однократной C++ replay initialization, повторной инициализации без изменения
state и прерывания установки в шести стадиях. Unit renderer отдельно проверяет
ограничение privileges и отсутствие runtime-init. Это тесты installer на
временном filesystem root, не запуск transparent unit в systemd.
Общий normal regression-набор — **169/169**, без skip; восемь новых installer
тестов проходят также с ASAN/UBSAN engine. Namespace-прогон с урезанными
capabilities пройден отдельно после общего набора.

Регрессия **boring-tls** site с обновлённым общим installer/renderer: две загрузки
NIC-less QEMU, **17/17** gates, `status=passed`. Отчёт:
`/var/tmp/meshpn-native-lab-abc7C7/report.json` (2026-10-07). Проверены
client/exit crash-restart, guard drift/refusal, reboot autostart/DNS, inventory и
порядок guard-before-uplink, stop-target fail-closed. Этот отчёт не подменяет
VM boot-приёмку **transparent**.

Transparent boot checkpoint 2026-10-07: **19/19** gates, две загрузки NIC-less
QEMU с systemd PID 1 и настоящим fresh installer. Проверены direct C++ сервисы,
обычный autorestart, отдельные crash-окна, stop-target fail-closed, reboot
autostart, сохранность replay-байтов и приватных прав, отказ missing/corrupt
state без runtime-init. Отчёт: `fixtures/clean-vpn-native-transparent-boot-report.json`.
Регрессия **173/173**, CTest **5/5** normal и **5/5** ASAN/UBSAN.
Повторная boring-tls site VM с этим renderer: **17/17** на двух загрузках,
`/var/tmp/meshpn-native-lab-rvHSAf/report.json`.
Production target теперь явно упорядочен после своего engine/coordinator.
Fixture persistence сохраняет права каталогов, не ослабляя проверки replay.
Физические устройства, production update, key rotation и скорость не проверялись.
