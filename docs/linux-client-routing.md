# Linux client: TUN и policy routing (две фазы)

Один непротиворечивый поток для **клиента** с `tun.defaultRoute: true` и `enableTun: true`. Exit-нода использует только mesh-маршрут и NAT, без split-default.

## Фаза A — поднятие интерфейса (`TunInterface.open` → `_configureLinuxTunAsync`)

Выполняется сразу после регистрации в mesh.

1. `ip addr add <virtualIp>/16 dev <tun>`
2. `ip link set dev <tun> mtu … up`
3. `ip route add <10.x.0.0/16> dev <tun>` (в **main**)
4. Асинхронно собирается список infra IPv4 (`collectInfraIPv4FromMeshConfigAsync`: signalling, dataServer, TURN/STUN из конфига, `excludeFromVPN`, `SIGNALLING_SERVER`) — **на фазе B список пересобирается заново** (актуальные DNS для STUN).
5. Если включён Linux full tunnel (`defaultRoute` и не exit): выставляется `_policyRoutingDeferred = true`, split-default и table 100 **ещё не** трогаются.
6. Если **не** отложенный режим: сразу вызывается `_configureDNS(null)` при `defaultRoute`.
7. Лог: при отложенном режиме — что DNS (`tun.dnsViaVpn`) применится только после фазы B, если включено.

## Фаза B — после первого `peer-connected` (WebRTC)

Вызывается из `MeshNode` с задержкой `tun.deferPolicyRoutingDelayMs` (по умолчанию 3000 ms), для не-WebRTC транспорта — сразу.

1. `_removeDnsRoutesFromMain` — снятие старых `/32` на публичные DNS с dev tun (идемпотентно).
2. Повторный вызов **`collectInfraIPv4FromMeshConfigAsync`** — свежая резолюция имён STUN/TURN перед `ip route`.
3. `_setupLinuxPolicyRouting(infra, prefix)`:
   - `ip rule` / flush table **100**
   - `ip route flush table 100`
   - для каждого infra IP: маршрут в table 100 и **replace `<ip>/32`** в **main** через uplink (+ `prefsrc` при наличии)
   - `default` в table 100 через uplink
   - если `linuxSplitDefault !== false`: `ip route replace 0.0.0.0/1 dev <tun>`, `128.0.0.0/1 dev <tun>`
   - `ip route replace <10.x.0.0/16> dev <tun>`
   - `ip rule add pref … fwmark 0x1 lookup 100`
   - `iptables -t mangle` цепочка `MESHVPN-BYPASS`: MARK для TCP 22
   - опционально: **`ip route flush cache`** — если `tun.linuxFlushRouteCache !== false` (по умолчанию выполняется)
   - `rp_filter=2` на uplink и tun ([`linux-rp-filter.js`](../src/network/linux-rp-filter.js))
4. Если `tun.dnsViaVpn`: `_configureDNS` сразу или через `deferDnsAfterPolicyMs`. Если `dnsViaVpn: false` — **не** вызывать `_configureDNS` (только лог).

## Автоматический снимок в лог (`[TUN-DIAG]`)

При **`tun.logRouteDiag: true`** (в примере [client-node.json](../config/client-node.json) уже включено) узел **сам** выполняет `ip route get` для 8.8.8.8, 1.1.1.1 и для всех IPv4 из последнего infra-списка после фазы B, плюс `ip rule list` и начало `ip route show table main`. Снимок печатается:

1. сразу после успешной фазы B (`reason=after-phase-B-policy-routing`);
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

1. **Попробуйте отключить сброс кэша маршрутов** в конфиге клиента:

   ```json
   "tun": {
     "linuxFlushRouteCache": false
   }
   ```

   Перезапустите узел и проверьте, держится ли WebRTC 10+ минут. Если да — оставьте `false` или сделайте поведение постоянным в коде/доке.

2. **Глубже по UDP** (под root на клиенте, пока peer подключён):

   ```bash
   ip route get <TURN_IP>
   ss -uap | head
   # при наличии conntrack:
   conntrack -L 2>/dev/null | grep 3478 || true
   sudo tcpdump -ni eth0 host <TURN_IP> and udp
   ```

   Нужно увидеть, идут ли пакеты к TURN **после** строки `[TUN] Linux policy routing:` и **до** `ICE failed`. Если поток обрывается — смотреть coturn/фаервол и согласованность relay на обеих сторонах.

3. Если и **`linuxFlushRouteCache: false`** не помогает — фиксируйте вывод tcpdump/conntrack и рассматривайте разделение стека (netns / отдельный процесс для WebRTC), см. общий план отладки в репозитории.

## Критерии приёмки (ручные)

1. `linuxSplitDefault` не задан или `true`, **Peers: 1** не менее 10 минут после фазы B, нет `WebRTC … state: failed` из-за маршрутов. При падении при «правильном» `ip route get` к TURN — проверить сценарий с **`linuxFlushRouteCache: false`**.
2. `curl -4 ifconfig.me` с клиента показывает **публичный IP exit**, не uplink клиента (при полном туннеле).
3. Рестарт только клиента или только exit: повторное соединение без спама `Got a remote candidate without ICE transport` и без ложного закрытия нового PC из-за отложенного `peer-leave`.

См. также [README.md](../README.md) раздел «Client (Linux): full tunnel».
