# Mesh VPN

Децентрализованная mesh VPN система с WebRTC, onion-шифрованием и multipath routing.

## Возможности

- **Mesh сеть** — все узлы связаны между собой, автоматический поиск маршрутов
- **WebRTC** — P2P соединения через NAT с помощью STUN/TURN
- **Onion encryption** — многослойное шифрование, relay узлы не видят содержимое
- **Multipath** — параллельная передача через несколько маршрутов
- **Exit nodes** — несколько выходных узлов с автоматическим failover
- **Transport fallback** — WebRTC → QUIC → WebSocket

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
npm run exit
# или
node src/index.js --role exit --signalling ws://localhost:8080
```

### Запуск relay node

```bash
npm run relay
# или
node src/index.js --role relay --signalling ws://localhost:8080
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

- `SIGNALLING_SERVER` — URL signalling сервера
- `NODE_ROLE` — роль узла (client/relay/exit)

### Аргументы командной строки

```
--role, -r <role>        Роль: client, relay, exit
--signalling, -s <url>   URL signalling сервера  
--config, -c <path>      Путь к конфигу
--key, -k <key>          Приватный ключ (base64)
```

## Настройка системы

### Linux

```bash
sudo ./scripts/setup-linux.sh exit eth0
```

### macOS

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

### Exit Node

- Выпускает трафик в интернет
- Выполняет NAT
- Возвращает ответы клиентам

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
│   ├── index.js           # Entry point
│   ├── core/
│   │   ├── node.js        # MeshNode class
│   │   ├── router.js      # Mesh routing
│   │   ├── scheduler.js   # Multipath scheduler
│   │   └── graph.js       # Network topology
│   ├── crypto/
│   │   ├── identity.js    # Ed25519 keys
│   │   ├── session.js     # X25519 key exchange
│   │   ├── encrypt.js     # AES-256-GCM
│   │   └── onion.js       # Onion encryption
│   ├── transport/
│   │   ├── webrtc.js      # WebRTC via werift
│   │   ├── quic.js        # QUIC fallback
│   │   ├── websocket.js   # WebSocket fallback
│   │   └── manager.js     # Transport abstraction
│   ├── network/
│   │   ├── tun.js         # TUN interface
│   │   ├── packet.js      # Packet format
│   │   └── ip-manager.js  # Virtual IP manager
│   ├── control/
│   │   ├── signalling.js  # Signalling client
│   │   └── discovery.js   # Peer discovery
│   └── exit/
│       └── nat.js         # NAT forwarding
├── server/
│   ├── signalling-server.js
│   └── turn-setup.md
├── config/
│   ├── default.json
│   ├── exit-node.json
│   └── relay-node.json
└── scripts/
    ├── setup-linux.sh
    └── setup-macos.sh
```

## Требования

- Node.js >= 18
- Linux или macOS
- Root/sudo для TUN интерфейса

## Лицензия

MIT
