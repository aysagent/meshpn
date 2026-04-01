# Linux client: TUN и policy routing (две фазы)

Один непротиворечивый поток для **клиента** с `tun.defaultRoute: true` и `enableTun: true`. Exit-нода использует только mesh-маршрут и NAT, без split-default.

## Фаза A — поднятие интерфейса (`TunInterface.open` → `_configureLinuxTunAsync`)

Выполняется сразу после регистрации в mesh.

1. `ip addr add <virtualIp>/16 dev <tun>`
2. `ip link set dev <tun> mtu … up`
3. `ip route add <10.x.0.0/16> dev <tun>` (в **main**)
4. Асинхронно собирается список infra IPv4 (`collectInfraIPv4FromMeshConfigAsync`: signalling, dataServer, TURN/STUN из конфига, `excludeFromVPN`, `SIGNALLING_SERVER`) — **на фазе B список пересобирается заново** (актуальные DNS для STUN).
5. Если включён Linux full tunnel (`defaultRoute` и не exit): выставляется `_policyRoutingDeferred = true`. **Сразу** применяются bypass infra (`/32` на TURN/STUN и т.д.), table 100, mesh `/16`, iptables/rp_filter — **без** маршрутов `0.0.0.0/1` и `128.0.0.0/1`, если они отложены (см. ниже).
6. Если **не** отложенный режим: сразу вызывается `_configureDNS(null)` при `defaultRoute`.
7. Лог: при отложенном режиме — что DNS (`tun.dnsViaVpn`) применится только после фазы B, если включено.

## Фаза B — после первого `peer-connected` (WebRTC)

Вызывается из `MeshNode` с задержкой `tun.deferPolicyRoutingDelayMs` (по умолчанию 3000 ms), для не-WebRTC транспорта — сразу.

1. `_removeDnsRoutesFromMain` — снятие старых `/32` на публичные DNS с dev tun (идемпотентно).
2. Повторный вызов **`collectInfraIPv4FromMeshConfigAsync`** — свежая резолюция имён STUN/TURN перед `ip route`.
3. **Ветка «ранняя infra уже есть»** (типичный Linux full tunnel): добавляются только **`0.0.0.0/1` и `128.0.0.0/1` на tun**, если `linuxSplitDefault !== false`. Опционально **`linuxSplitDefaultDelayAfterPeerMs > 0`** откладывает именно этот шаг на указанное число миллисекунд после первого вызова фазы B (после `deferPolicyRoutingDelayMs`), чтобы ICE/DC успели стабилизироваться; таймер отменяется при **`peer-disconnected`**.
4. **Иначе** выполняется полный **`_setupLinuxPolicyRouting(infra, prefix)`** (все шаги сразу): `ip rule` / flush table **100**, `/32` infra в main и table 100, при необходимости split `/1`, mesh `/16`, iptables `MESHVPN-BYPASS`, опционально `ip route flush cache`, `rp_filter=2` ([`linux-rp-filter.js`](../src/network/linux-rp-filter.js)).
5. Если `tun.dnsViaVpn`: `_configureDNS` сразу или через `deferDnsAfterPolicyMs`. Если `dnsViaVpn: false` — **не** вызывать `_configureDNS` (только лог).

### Параметры стабильности

| Параметр | Смысл |
|----------|--------|
| `linuxSplitDefault: false` | Нет маршрутов `0.0.0.0/1` — **clearnet не уходит в tun**; долгий прогон проверяет, связан ли обрыв ICE именно с split-default. |
| `linuxSplitDefault: true` + `linuxSplitDefaultDelayAfterPeerMs` (напр. `60000`) | Full tunnel с отложенным включением `/1` после стабильного DC. |
| `linuxFlushRouteCache: false` | Не вызывать `ip route flush cache` при настройке маршрутов. |
| `logRouteDiagSs: true` | В `[TUN-DIAG]` добавить первые строки вывода `ss -uap`. |

## Автоматический снимок в лог (`[TUN-DIAG]`)

При **`tun.logRouteDiag: true`** (в примере [client-node.json](../config/client-node.json) уже включено) узел **сам** выполняет `ip route get` для 8.8.8.8, 1.1.1.1 и для всех IPv4 из последнего infra-списка после фазы B, плюс `ip rule list` и начало `ip route show table main`. При **`tun.logRouteDiagSs: true`** добавляется начало вывода **`ss -uap`**. Снимок печатается:

1. сразу после успешной фазы B (`reason=after-phase-B-policy-routing` или `after-phase-B-split-default-delayed`, если split `/1` включался с задержкой `linuxSplitDefaultDelayAfterPeerMs`);
2. при обрыве WebRTC на клиенте (`reason=webrtc-peer-disconnected:…`).

Достаточно **скопировать блоки между `[TUN-DIAG] ---` и передать их для разбора**. Отключить шум: `"logRouteDiag": false`.

## WebRTC: порядок ICE и `hsGen` в signalling

Trickle **ICE** иногда приходит **раньше** нового **offer** при reconnect. Старый фильтр «любой `hsGen !== expected` — drop» ошибочно отбрасывал кандидаты нового handshake (`hsGen=2` при ещё не обновлённом `expected=1`). В [`discovery.js`](../src/control/discovery.js) отбрасывается только **`hsGen < expected`**; при **`hsGen > expected`** ожидание обновляется и кандидат передаётся в WebRTC (очередь до `setRemoteDescription`). При **`peer-disconnected`** сбрасывается `_expectedRemoteIceHsGen` для пира.

## Команды для диагностики вручную (по желанию)

На клиенте **до** и **сразу после** строки в логе `[TUN] Linux policy routing:` / `[TUN] Linux full tunnel:`:

```bash
# Замените на IP вашего TURN из конфига
ip route get 62.84.120.30
ip route get 8.8.8.8
```

Ожидание для TURN: путь через **uplink** (например `dev eth0`), не через `dev tun0`.

Опционально:

```bash
sudo tcpdump -ni eth0 udp port 3478
```

Убедиться, что до/после фазы B есть обмен UDP с TURN.

## ICE падает после фазы B, но `ip route get` к TURN уже через uplink

Если **`ip route get <TURN_IP>`** показывает **eth0** (или другой uplink), а не **tun0**, простой «добавить TURN в exclude» часто уже не причина: таблица **main** для этого dst выглядит верно.

Если в логе сначала **`ICE: completed`**, затем **`[TUN] Добавление split-default`** (или отложенный split), затем через десятки секунд **`state: failed`** — проверьте **отдельно**:

1. **`linuxSplitDefault: false`** и прогон **10+ минут** (в примере [client-node.json](../config/client-node.json) сейчас так для диагностики). Если связь стабильна — проблема связана с маршрутами **`0.0.0.0/1` / `128.0.0.0/1`**; для full tunnel включите снова `true` и добавьте **`linuxSplitDefaultDelayAfterPeerMs`** (например `60000`).
2. **tcpdump** на клиенте под root в одном окне с логами узла (замените IP на ваш TURN):

   ```bash
   sudo tcpdump -ni eth0 host 62.84.120.30 and udp -c 200
   ```

   Нужны пакеты **после** строки про split-default и **до** `ICE failed`. Если трафик к TURN пропадает — смотреть ядро/conntrack; если идёт — смотреть **coturn** и стек WebRTC.

3. **coturn**: логи `turnserver` в момент обрыва (таймаут allocation/channel, auth, `no relay` и т.д.); параметры **lifetime** / **channel lifetime** в `turnserver.conf`.

4. **Попробуйте отключить сброс кэша маршрутов** в конфиге клиента:

   ```json
   "tun": {
     "linuxFlushRouteCache": false
   }
   ```

   Перезапустите узел и проверьте, держится ли WebRTC 10+ минут. Если да — оставьте `false` или сделайте поведение постоянным в коде/доке.

5. **Глубже по UDP** (под root на клиенте, пока peer подключён):

   ```bash
   ip route get <TURN_IP>
   ss -uap | head
   # при наличии conntrack:
   conntrack -L 2>/dev/null | grep 3478 || true
   ```

   Либо включите **`logRouteDiagSs: true`** — часть информации попадёт в `[TUN-DIAG]`.

6. Если и **`linuxFlushRouteCache: false`**, и **`linuxSplitDefaultDelayAfterPeerMs`**, и отключение split не дают картины — фиксируйте tcpdump/conntrack/coturn и рассматривайте разделение стека (netns / отдельный процесс для WebRTC).

## Критерии приёмки (ручные)

1. С нужной комбинацией **`linuxSplitDefault`**, **`linuxSplitDefaultDelayAfterPeerMs`**, **`linuxFlushRouteCache`** — **Peers: 1** не менее 10 минут после появления split `/1` (или без них при `linuxSplitDefault: false`), нет `WebRTC … state: failed` из-за маршрутов.
2. `curl -4 ifconfig.me` с клиента показывает **публичный IP exit**, не uplink клиента (при полном туннеле).
3. Рестарт только клиента или только exit: повторное соединение без спама `Got a remote candidate without ICE transport` и без ложного закрытия нового PC из-за отложенного `peer-leave`.

См. также [README.md](../README.md) раздел «Client (Linux): full tunnel».
