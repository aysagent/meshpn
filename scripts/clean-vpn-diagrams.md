# Диаграммы: `clean-vpn.js`

Архитектура и потоки данных для [`scripts/clean-vpn.js`](clean-vpn.js).

---

## 1. Общая архитектура (client ↔ exit)

```mermaid
flowchart TB
  subgraph hostClient [Client host Linux]
    Apps[Приложения / LAN]
    KernelC[Ядро: маршруты split-default]
    TunC["tunN 10.99.0.2 ↔ peer 10.99.0.1"]
    ProcC["node clean-vpn.js --role=client"]
    Apps --> KernelC
    KernelC --> TunC
    TunC <--> ProcC
    ProcC --> IptC["iptables optional: transparent-tls / LAN"]
  end

  subgraph tunnel [Туннель по --type]
    Wire["TCP / TLS / WS / UDP / QUIC / WebRTC DC"]
  end

  subgraph hostExit [Exit host Linux]
    ProcE["node clean-vpn.js --role=exit"]
    TunE["tunN 10.99.0.1 ↔ peer 10.99.0.2"]
    NatE["iptables MASQUERADE + FORWARD"]
    Ext[eth0 / uplink в интернет]
    ProcE <--> TunE
    TunE --> NatE
    NatE --> Ext
  end

  ProcC --> Wire
  Wire --> ProcE
```

| Роль | TUN | Сеть на хосте |
|------|-----|----------------|
| **client** | `10.99.0.2` | С `--split-default`: IPv4 default → tun (`0.0.0.0/1` + `128.0.0.0/1`), RFC1918 → uplink; bypass к `--server` |
| **exit** | `10.99.0.1` | NAT трафика с tun в `--ext` (или default route) |

---

## 2. Точка входа и ветвление

```mermaid
flowchart TD
  Start([argv: role server type ...]) --> Linux{platform linux?}
  Linux -->|нет| ErrExit[exit 1]
  Linux -->|да| Parse[parseArgs]
  Parse --> Role{--role}
  Role -->|exit| RunExit[runExit]
  Role -->|client| RunClient[runClient]
  RunExit --> TunOpen[openTunNative + setupTunIp]
  RunClient --> TunOpen2[openTunNative + setupTunIp]
  TunOpen --> ExitNat[setupExitNat iptables]
  ExitNat --> TypeExit{--type}
  TunOpen2 --> Routes[setupClientRoutesAsync]
  Routes --> LanOpt["setupClientLanGateway optional"]
  LanOpt --> TypeClient{--type}
  TypeExit --> TransExit[слушатель / connect по типу]
  TypeClient --> TransClient[connect / listen по типу]
  TransExit --> BridgeE[attachTunBridge]
  TransClient --> BridgeC[attachTunBridge + TTL paths]
  BridgeE --> Loop[цикл до SIGINT]
  BridgeC --> Loop
  Loop --> Shutdown[shutdown: iptables routes tun]
```

---

## 3. Ядро: мост TUN ↔ транспорт

Все «обычные» VPN-типы сходятся в **`attachTunBridge`** (фильтр **`isIpv4Bridgeable`** — сейчас только IPv4).

```mermaid
flowchart LR
  subgraph tunSide [TUN native addon]
    ReadTun[tun.read]
    WriteTun[tun.write]
  end

  subgraph bridge [attachTunBridge]
    Filter[isIpv4Bridgeable]
    IcmpLocal["ICMP echo reply 10.99.0.1/2"]
    Framer[StreamFramer uint32 BE + pkt]
    KeepAlive["keep-alive / lazy reconnect optional"]
  end

  subgraph wireSide [endpoint по transport]
    TCP["socket http tls boring-tls"]
    WS[websocket binary]
    UDP[udp datagram]
    QUIC[quic quic-ext stream]
    DC[webrtc DataChannel]
  end

  ReadTun --> Filter
  Filter -->|ok| Framer
  Filter -->|local IP| IcmpLocal
  IcmpLocal --> WriteTun
  Framer --> wireSide
  wireSide --> Framer
  Framer --> WriteTun
```

**Протокол на потоковых транспортах** (socket, http после преамбулы, tls/h2, quic bidi):

```
[4 байта BE длина][сырой IPv4-пакет L3]
```

На **WebSocket / UDP / WebRTC DC** — одно сообщение/датаграмма = один пакет **без** префикса длины.

---

## 4. Слой транспортов (`--type`)

```mermaid
flowchart TB
  subgraph common [Общее для обеих ролей]
    TUN[tun_linux N-API]
    Bridge[attachTunBridge]
    TUN --> Bridge
  end

  subgraph stream [Поток + uint32 framing]
    socket[socket]
    http[http GET /clean-vpn]
    tls[tls Bearer HMAC h2 or http11]
    boring[boring-tls helper subprocess]
    quicN[node quic ALPN clean-vpn]
    quicE[quic-ext infisical ALPN clean-vpn-ext]
  end

  subgraph message [Сообщение = 1 пакет]
    ws[websocket]
    udp[udp]
    webrtc[webrtc DC + WS signaling]
  end

  subgraph chrome [Puppeteer client only]
    wsChrome[ws-chrome]
    rtcChrome[rtc-chrome → exit webrtc]
  end

  subgraph mux [Мультиплекс на одном TCP :443]
    combo[combo-tls exit: CVPTX or TLS mux]
    trans[transparent-tls + iptables REDIRECT]
  end

  Bridge --> stream
  Bridge --> message
  Bridge --> chrome
  combo --> Bridge
  trans --> Bridge
```

**Сигналинг (отдельно от IP-пакетов):** `webrtc`, `udp --punch`, `rtc-chrome` — WebSocket JSON; данные — DataChannel или UDP после punch.

---

## 5. Client: маршрутизация и LAN

```mermaid
flowchart TD
  Uplink[default route dev gw]
  Server["--server HOST:PORT"]
  TunDev[tun interface]

  Server --> Bypass["/32 к HOST через uplink"]
  Uplink --> Bypass

  subgraph split ["--split-default"]
    Half1["0.0.0.0/1 → tun"]
    Half2["128.0.0.0/1 → tun"]
    Rfc["10/8 172.16/12 192.168/16 → uplink"]
  end

  Uplink --> split
  split --> TunDev

  subgraph lan ["--client-lan-subnet optional"]
    LanHosts[LAN устройства]
    Snat["iptables SNAT → 10.99.0.2"]
    Fwd[FORWARD LAN → tun]
  end

  LanHosts --> Snat --> TunDev
```

Без `--split-default` на tun всё равно может быть трафик к peer `10.99.0.1` и IPv6 ND; в мост уходит только валидный **IPv4**.

---

## 6. Exit: NAT и TLS-ветки

```mermaid
flowchart TD
  Internet[Интернет]
  ExtIf["--ext или default NIC"]
  TunIn[пакеты с tun src 10.99.0.x]

  TunIn --> Fwd[FORWARD tun → ext]
  Fwd --> Masq["POSTROUTING MASQUERADE"]
  Masq --> ExtIf
  ExtIf --> Internet
  Internet --> ExtIf
  ExtIf --> Fwd
  Fwd --> TunIn

  subgraph tlsExit ["--type=tls или combo-tls"]
    Listen[TCP :443 listen]
    Listen --> ParseCH[разбор ClientHello]
    ParseCH -->|SNI mismatch / parse fail| Pass[TLS passthrough → probe target]
    ParseCH -->|Bearer OK| VPN[HTTP h2/1.1 → attachTunBridge]
    Listen -->|combo + prefix CVPTX| Relay[HTTPS transparent relay]
    Listen -->|combo без CVPTX| VPN
  end
```

---

## 7. `transparent-tls` / `combo-tls` на client (два канала)

```mermaid
flowchart TB
  subgraph pathA [Канал A: VPN как socket]
    TunA[TUN IPv4] --> BridgeA[attachTunBridge TCP mux]
    BridgeA --> ExitA[exit: TUN + NAT]
  end

  subgraph pathB [Канал B: перехват HTTPS :443]
    App[приложение tcp/443]
    App --> IptOut["iptables OUTPUT REDIRECT"]
    IptOut --> LocalSrv["127.0.0.1 intercept"]
    LocalSrv --> CVPTX["префикс CVPTX → TCP к exit"]
    CVPTX --> ExitRelay[exit: relay HTTPS]
  end

  subgraph lanB [с --client-lan-subnet]
    Lan443[LAN :443] --> Preroute["PREROUTING DNAT"]
    Preroute --> LocalSrv
  end
```

На **client** `combo-tls`: TUN через **boring-tls-helper** (как `boring-tls`) + канал B как у `transparent-tls`.

---

## 8. Зависимости (вне Node)

```mermaid
flowchart LR
  CVPN[clean-vpn.js]
  CVPN --> TunAddon["native/tun_linux"]
  CVPN --> IpCmd["ip route addr"]
  CVPN --> Ipt["iptables"]
  CVPN --> Boring["boring-tls-helper optional"]
  CVPN --> QuicPkg["@infisical/quic optional"]
  CVPN --> Ndc["node-datachannel optional"]
  CVPN --> Puppeteer["puppeteer ws-chrome rtc-chrome"]
  CVPN --> Certs["certs/ clean-vpn-hmac.key"]
```

---

## Легенда

| Элемент | Значение |
|---------|----------|
| `10.99.0.1` / `10.99.0.2` | exit / client на TUN |
| `StreamFramer` | `uint32 BE` + L3 для TCP/TLS/QUIC-stream |
| `isIpv4Bridgeable` | сейчас только IPv4 в туннель |
| SIGINT/SIGTERM | откат маршрутов, iptables, закрытие tun |
