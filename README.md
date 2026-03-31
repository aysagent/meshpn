# Mesh VPN

Децентрализованная mesh VPN система с WebRTC, onion-шифрованием и multipath routing.

## Run
- sudo env PATH=$PATH SIGNALLING_SERVER=62.84.120.30:8888 npm run sig:exit
- sudo env PATH=$PATH node src/index.js --role client --signalling ws://62.84.120.30:8080

## Возможности

- **Mesh сеть** — все узлы связаны между собой, автоматический поиск маршрутов
- **WebRTC** — P2P соединения через NAT с помощью STUN/TURN
- **Onion encryption** — многослойное шифрование, relay узлы не видят содержимое
- **Multipath** — параллельная передача через несколько маршрутов
- **Exit nodes** — несколько выходных узлов с автоматическим failover
- **Transport fallback** — WebRTC → QUIC → WebSocket
- **Client-Relay** — комбинированная роль для одновременной работы как клиент и relay

## Архитектура

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│    Relay    │────▶│  Exit Node  │────▶ Internet
│  (TUN/VPN)  │     │  (forward)  │     │   (NAT)     │
└─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
                    Mesh Network
```

## Быстрый старт

### Установка

```bash
npm install
```

### Запуск signalling сервера

```bash
npm run server
# или
node server/signalling-server.js
```

### Запуск клиента

```bash
npm run client
# или
node src/index.js --role client --signalling ws://localhost:8080
```

### Запуск exit node

```bash
# Запустить exit node (NAT настраивается автоматически)
sudo npm run exit

# или
sudo node src/index.js --role exit --signalling ws://localhost:8080
```

NAT включается автоматически после создания TUN интерфейса и откатывается при завершении (Ctrl+C).

Подробнее о настройке NAT: [server/nat-setup.md](server/nat-setup.md)

### Запуск relay node

```bash
npm run relay
# или
node src/index.js --role relay --signalling ws://localhost:8080
```

### Запуск client-relay node

Комбинированный режим: работает как клиент (с TUN интерфейсом) и одновременно пересылает трафик других узлов.

```bash
node src/index.js --role client-relay --signalling ws://localhost:8080
```

## Конфигурация

### config/default.json

```json
{
  "role": "client",
  "signallingServer": "ws://localhost:8080",
  "iceServers": [
    { "urls": "stun:stun.l.google.com:19302" }
  ],
  "turnServers": [
    {
      "urls": "turn:your-turn-server:3478",
      "username": "user",
      "credential": "pass"
    }
  ]
}
```

### Переменные окружения

- `SIGNALLING_SERVER` — URL signalling сервера; для **exit** на другой машине, чем signalling, задавайте публичный `ws://host:8080`, а не `localhost`
- `NODE_ROLE` — роль узла (client/relay/client-relay/exit)

### Аргументы командной строки

```
--role, -r <role>        Роль: client, relay, exit
--signalling, -s <url>   URL signalling сервера  
--config, -c <path>      Путь к конфигу
--key, -k <key>          Приватный ключ (base64)
```

## Настройка системы

### NAT для Exit Node

NAT настраивается **автоматически** при запуске exit node:

```bash
sudo npm run exit
```

При завершении (Ctrl+C) настройки NAT откатываются автоматически.

#### Ручное управление (fallback)

```bash
# Включить NAT (автоматически определяет ОС и интерфейс)
npm run nat:enable

# Включить NAT с указанием интерфейса
npm run nat:enable -- eth0

# Выключить NAT и восстановить исходные настройки
npm run nat:disable
```

Скрипты автоматически сохраняют исходные настройки системы в `~/.mesh-vpn-backup/` и восстанавливают их при отключении.

Подробная документация: [server/nat-setup.md](server/nat-setup.md)

### Client (Linux): full tunnel (IPv4)

При `tun.defaultRoute: true` (или если ключ не задан — по умолчанию включён) **клиент Linux** настраивает full tunnel **без** глобального правила `ip rule from all lookup 100` (оно ломало UDP/TURN при переключении маршрутизации).

Схема:

- В **`main`**: маршруты **`0.0.0.0/1`** и **`128.0.0.0/1`** на **`dev <tun>`** (весь IPv4 попадает в туннель по принципу «две половины»), маршрут к mesh **`10.200.0.0/16`**, узкие **`/32` через uplink** к IPv4 инфраструктуры (signalling/TURN/STUN/exclude) — **длиннее префикса**, чем `/1`, поэтому TURN и STUN идут мимо туннеля; маршруты к резолверам DNS (`8.8.8.8` и др.) через TUN в `main`, совместно с подменой `/etc/resolv.conf`.
- Таблица **`100`**: только **`default` через uplink** и те же **infra `/32`**, чтобы по **`ip rule fwmark 0x1 lookup 100`** обходить туннель **SSH** (и только он маркируется).
- **`iptables -t mangle`**, цепочка **`MESHVPN-BYPASS`**: маркирует исходящий TCP с `--sport 22` / `--dport 22` (conntrack), **`fwmark 0x1`** → **`lookup 100`** → физический default.

Для **доменных имён** в конфиге и в **`tun.excludeFromVPN`** выполняется DNS (`resolve4`), как раньше. Литеральные IPv4 добавляются без DNS.

Перехват DNS (`/etc/resolv.conf` и маршруты к резолверам) выполняется **только** при full tunnel на клиенте, **не** на exit-ноде.

**Отложенная policy routing:** при `tun.deferPolicyRoutingUntilWebRtcConnected: true` split-маршруты и `ip rule` для fwmark применяются **после** первого `peer-connected` (с задержкой `tun.deferPolicyRoutingDelayMs`, по умолчанию 3000 ms). По умолчанию `false`.

**Конфликты:** приоритет правила `fwmark` и mark `0x1` могут пересечься с Docker, WireGuard или другим VPN — проверьте `ip rule list` и `ip route show table 100` / `ip route show`.

**IPv6:** эта схема нацелена на **IPv4**; для SSHv6 и инфраструктуры по IPv6 нужны отдельные правила и таблицы.

### Client (macOS)

Поведение **macOS** при full tunnel **не меняется**: отдельного `ip rule`/отдельной таблицы, как в Linux, нет; используется прежняя настройка TUN-интерфейса и маршрутов через системные утилиты.

### Диагностика: клиент на VPS, exit в другой сети (Multipass, домашний NAT)

Если **signalling** на VPS, а **exit** в виртуалке/дома, типичные причины «на VPS не работают ping/curl» при full tunnel:

1. **URL signalling для exit** — внутри ВМ `localhost` — это сама ВМ, а не VPS. Задайте явно: `SIGNALLING_SERVER=ws://<PUBLIC_IP_VPS>:8080` или `node src/index.js --role exit --signalling ws://<PUBLIC_IP_VPS>:8080 -c config/exit-node-linux.json`. Предупреждение при старте `[CONFIG] Роль exit: signallingServer указывает на localhost` указывает на ту же проблему.
2. **TURN/STUN** — адреса в `turnServers` / `iceServers` должны указывать на хост, **доступный с VPS и с exit** (часто публичный IP с coturn). Замените примерные IP в конфигах на свои.
3. **Разделить mesh и policy routing** — временно `"tun": { "defaultRoute": false }` у клиента и перезапуск. Если ping/curl к интернету **снова работают**, проблема в пути **к exit в mesh** (WebRTC/TURN), а не в таблице маршрутизации 100.
4. **Логи** — при отсутствии пути к exit: `[MESH] Нет достижимого exit…` и периодически `[TUN] Нет маршрута к exit…`. Сообщение `[WS-DATA] WebSocket data server listening on port 8081` на exit относится к опциональному `dataServerPort`, это не signalling (8080).

**Проверка маршрутов (client Linux, full tunnel):** `ip route show table 100`, `ip route get <DST> table 100` — для IP TURN и нескольких IP из `dig stun.l.google.com +short` путь не должен быть через `dev tun` (кроме самого mesh). Сравните с рабочей машиной (например Multipass). Если TURN на том же хосте, что и клиент, и что-то всё ещё уходит в tun, добавьте IP в **`tun.excludeFromVPN`**.

**Hairpin / тот же VPS:** при необходимости явно согласуйте URL TURN (публичный IP vs localhost) и DNS; для теста можно временно отключить публичные STUN в конфиге (осторожно с ICE).

**Если маршруты верны, а Peers:0:** смотрите фаервол coturn, UDP, NAT на стороне exit в Multipass (`tcpdump`, логи ICE).

### Ручная настройка

#### Linux

```bash
sudo ./scripts/setup-linux.sh exit eth0
```

#### macOS

```bash
sudo ./scripts/setup-macos.sh exit en0
```

## Типы узлов

### Client

- Создает TUN интерфейс
- Генерирует VPN трафик
- Выбирает exit node
- Строит onion маршрут

### Relay

- Пересылает пакеты
- Снимает свой слой шифрования
- Не видит содержимое трафика

### Client-Relay

- Комбинация client и relay
- Создает TUN интерфейс (как client)
- Пересылает пакеты других узлов (как relay)
- Регистрируется как relay для маршрутизации
- Позволяет использовать VPN и помогать сети одновременно

### Exit Node

- Создает TUN интерфейс
- Инжектирует расшифрованные пакеты в TUN
- Использует системный NAT (iptables/pf) для выхода в интернет
- Возвращает ответы клиентам через mesh сеть

## Криптография

- **Identity**: Ed25519 — подпись и идентификация
- **Key Exchange**: X25519 ECDH — обмен ключами
- **Encryption**: AES-256-GCM — шифрование данных
- **Key Derivation**: HKDF-SHA256 — деривация ключей
- **Onion**: Многослойное шифрование по маршруту

## Виртуальная сеть

- Диапазон: `10.200.0.0/16`
- Автоматическое назначение IP при регистрации
- Маршрутизация по виртуальным IP

## TURN сервер

Подробная инструкция: [server/turn-setup.md](server/turn-setup.md)

```bash
# Ubuntu/Debian
sudo apt install coturn

# Конфигурация /etc/turnserver.conf
listening-port=3478
realm=mesh-vpn
user=meshuser:meshpass
lt-cred-mech
```

## API

### MeshNode

```javascript
import { MeshNode } from './src/core/node.js';

const node = new MeshNode({
  role: 'client',
  signallingServer: 'ws://localhost:8080'
});

await node.start();

node.on('peer-connected', (peerId) => {
  console.log('Connected:', peerId);
});

node.on('registered', (info) => {
  console.log('Virtual IP:', info.virtualIp);
});
```

### Identity

```javascript
import { Identity } from './src/crypto/index.js';

const identity = new Identity();
console.log('Node ID:', identity.nodeId);
console.log('Public Key:', identity.exportPublicKey());

// Подпись
const signature = identity.sign('message');

// Верификация
Identity.verify('message', signature, identity.publicKey);
```

## Структура проекта

```
mesh-vpn/
├── src/
│   ├── index.js              # Entry point
│   ├── core/
│   │   ├── index.js          # Module exports
│   │   ├── node.js           # MeshNode class
│   │   ├── router.js         # Mesh routing
│   │   ├── scheduler.js      # Multipath scheduler
│   │   └── graph.js          # Network topology
│   ├── crypto/
│   │   ├── index.js          # Module exports
│   │   ├── identity.js       # Ed25519 keys
│   │   ├── session.js        # X25519 key exchange
│   │   ├── encrypt.js        # AES-256-GCM
│   │   └── onion.js          # Onion encryption
│   ├── transport/
│   │   ├── index.js          # Module exports
│   │   ├── manager.js        # Transport abstraction
│   │   ├── webrtc.js         # WebRTC via werift
│   │   ├── quic.js           # QUIC fallback
│   │   └── websocket.js      # WebSocket fallback
│   ├── network/
│   │   ├── index.js          # Module exports
│   │   ├── tun.js            # TUN interface (Linux/macOS)
│   │   ├── packet.js         # IP packet parsing/building
│   │   └── ip-manager.js     # Virtual IP manager
│   ├── control/
│   │   ├── index.js          # Module exports
│   │   ├── signalling.js     # Signalling client
│   │   └── discovery.js      # Peer discovery
│   └── exit/
│       ├── index.js          # Module exports
│       └── nat.js            # NAT mapping table
├── server/
│   ├── signalling-server.js  # Signalling server
│   ├── turn-setup.md         # TURN server setup guide
│   └── nat-setup.md          # System NAT setup guide
├── helpers/
│   ├── utun-helper.c         # macOS utun interface helper
│   └── Makefile              # Build helper binary
├── config/
│   ├── default.json          # Default configuration
│   ├── client-relay.json     # Client-relay config
│   ├── exit-node.json        # Exit node config
│   └── relay-node.json       # Relay node config
└── scripts/
    ├── nat-enable.sh         # Enable system NAT
    ├── nat-disable.sh        # Disable system NAT
    ├── setup-linux.sh        # Linux setup
    └── setup-macos.sh        # macOS setup
```

## Требования

- Node.js >= 18
- Linux или macOS
- Root/sudo для TUN интерфейса

## Лицензия

MIT
