# Native transparent: standalone network guard (laboratory checkpoint)

Сетевые правила и kernel REDIRECT обслуживаются control plane; ClientHello,
TLS, TCP relay и тестовые payload обрабатываются только C++. Это **не** готовая
установка на Radxa/VPS: systemd site installer пока намеренно отвергает этот
профиль. Нельзя применять его к действующему USB/TUN firewall.

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
  Автоматическое связывание engine config с профилем ещё предстоит в installer.

Используется общий `applyNativeNetworkProfile`: только пустые dedicated tables,
выбранные links DOWN, forwarding=0; pre-test правил, сначала IPv6/IPv4 DROP,
readback, journal stages и привязка к boot/network/user namespace. У transparent
в journal поле `tun=null` (унаследованное имя стадии `tun` не создаёт интерфейс).
Повторный запуск только сверяет правила/интерфейсы; partial install, чужие
правила, другая конфигурация или namespace требуют review без очистки/перезаписи.
Stop/SIGKILL engine не снимает firewall и REDIRECT. Concurrent network/firewall
administrators не поддерживаются. Адреса/default/DHCP — внешний владелец.

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
Следующий этап — immutable binding engine/network, fresh installer/systemd
target с gate интерфейсов и отдельная VM cold-boot/crash приёмка transparent.

Checkpoint 2026-10-07: общий native regression-набор **159/159**, без skip;
CTest **5/5** normal и ASAN/UBSAN; все четыре transparent-прогона (codec/TCP,
scoped engine, public-policy и новый network guard) прошли normal и ASAN/UBSAN.
Повторного VM boot-прогона в этом checkpoint не было. Radxa/VPS/Mac не менялись.
