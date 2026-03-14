Ниже — **сводное техническое задание (ТЗ)** на разработку **децентрализованной mesh-VPN системы** с relay-узлами, exit-nodes, мульти-транспортом, onion-шифрованием и multipath маршрутизацией. Архитектурно система вдохновлена решениями вроде WireGuard, Tailscale, ZeroTier и анонимизационной сетью Tor, но реализуется как собственный mesh-overlay.

---

# 1. Цель системы

Разработать **mesh VPN-сеть**, позволяющую:

* соединять клиентов через NAT
* маршрутизировать трафик через relay-узлы
* использовать несколько exit nodes
* автоматически искать маршруты
* поддерживать multipath передачу
* работать поверх WebRTC / QUIC / HTTPS
* обеспечивать end-to-end шифрование

---

# 2. Основные компоненты системы

Система состоит из трёх основных плоскостей.

## 2.1 Control Plane

Отвечает за:

* регистрацию узлов
* discovery peers
* обмен ключами
* сигналинг WebRTC

Компонент:

**Signalling Server**

Функции:

* WebSocket API
* регистрация узлов
* передача ICE кандидатов
* рассылка peer list

Он **не передает VPN трафик**.

---

## 2.2 Data Plane

Передача реального VPN-трафика.

Функции:

* маршрутизация mesh
* relay
* multipath
* exit node forwarding

Трафик проходит через:

```
TUN interface
↓
VPN encryption
↓
Mesh routing
↓
Transport
```

---

## 2.3 Transport Layer

Поддержка нескольких типов соединений между peer-узлами:

1. **WebRTC DataChannel** (основной канал)
2. **QUIC** (fallback)
3. **HTTPS/WebSocket** (последний fallback)

Транспорт выбирается автоматически.

---

# 3. Типы узлов

В сети существует три роли.

## 3.1 Client Node

Функции:

* создание TUN интерфейса
* генерация трафика
* выбор exit node
* построение маршрута
* onion encryption
* multipath scheduler

---

## 3.2 Relay Node

Функции:

* пересылка пакетов
* снятие одного onion-слоя
* передача следующему hop

Relay **не может расшифровать содержимое VPN пакетов**.

---

## 3.3 Exit Node

Функции:

* снятие последнего слоя шифрования
* отправка пакетов в интернет
* возврат ответов клиенту

---

# 4. Виртуальная сеть

Все узлы получают **виртуальный IP**.

Пример диапазона:

```
10.200.0.0/16
```

Пример:

```
client1 10.200.0.2
client2 10.200.0.3
exit1   10.200.0.10
```

Весь VPN-трафик проходит через **TUN интерфейс**.

---

# 5. Криптография

## 5.1 Identity keys

Каждый узел имеет постоянную пару ключей:

```
Ed25519
```

Используются для:

* идентификации
* подписи handshake

---

## 5.2 Session keys

При соединении узлов выполняется:

```
X25519 ECDH
```

Полученный shared secret проходит через:

```
HKDF
```

и превращается в ключ:

```
AES-256-GCM
```

---

## 5.3 Onion encryption

Каждый пакет шифруется слоями по маршруту:

```
encrypt(relay1,
   encrypt(relay2,
      encrypt(exitNode, payload)
   )
)
```

Каждый узел снимает только **свой слой**.

---

# 6. Mesh routing

Сеть представляет собой **граф соединений peer-узлов**.

Каждый узел хранит:

```
peer list
graph topology
exit nodes
```

---

## 6.1 Поиск маршрута

Маршрут до exit node ищется алгоритмом:

```
BFS
```

Пример маршрута:

```
client → relay1 → relay2 → exit
```

---

# 7. Multipath routing

Для повышения устойчивости используется **несколько маршрутов одновременно**.

Пример:

```
path1 client → relay1 → exit1
path2 client → relay2 → exit2
path3 client → relay3 → exit1
```

Пакеты распределяются по маршрутам scheduler-ом.

---

# 8. Packet format

Каждый пакет содержит:

```
flow_id
sequence_number
route
hop
payload
```

Пример:

```
{
 flow: "f123",
 seq: 345,
 route: ["relay1","relay2","exit1"],
 hop: 0,
 payload: encrypted
}
```

---

# 9. Packet reordering

Multipath может менять порядок доставки.

Клиент использует:

```
reorder buffer
```

который собирает пакеты по `sequence_number`.

---

# 10. Exit node selection

Клиент хранит список exit nodes.

Алгоритм выбора:

1. построить маршруты
2. измерить latency
3. выбрать лучший
4. fallback при недоступности

---

# 11. Relay behaviour

Relay-узел:

```
receive packet
decrypt own layer
increment hop
forward to next node
```

Relay **не знает конечный payload**.

---

# 12. Transport fallback

Каждый peer может иметь несколько каналов:

```
WebRTC
QUIC
HTTPS
```

При отправке выбирается первый живой транспорт.

При падении:

```
WebRTC → QUIC → HTTPS
```

---

# 13. NAT traversal

Используются:

* STUN
* TURN relay

TURN может работать на VPS.

---

# 14. Health monitoring

Периодически выполняются:

```
peer ping
route latency check
exit availability
```

Плохие маршруты удаляются.

---

# 15. Signalling server API

Протокол:

```
register
peers list
signal (offer/answer/ice)
peer join
peer leave
```

Транспорт:

```
WebSocket
```

---

# 16. Основные модули системы

Приложение делится на модули:

```
core/
  router.js
  scheduler.js
  graph.js

crypto/
  key_exchange.js
  onion.js
  encrypt.js

transport/
  webrtc.js
  quic.js
  https.js

network/
  tun.js
  packet.js

control/
  signalling.js
```

---

# 17. Требования к платформе

Минимальная поддержка:

* Linux
* macOS

Язык реализации:

```
Node.js
```

---

# 18. Основные свойства системы

Система должна обеспечивать:

* обход NAT
* end-to-end encryption
* multipath routing
* relay forwarding
* exit nodes
* transport fallback
* onion encryption

---

# 19. Масштабируемость

Сеть должна поддерживать:

```
1000+ nodes
```

без broadcast-штормов.

Маршрутизация должна использовать **direct routing**, а не broadcast.

---

# 20. Будущие улучшения

Для production-уровня рекомендуется добавить:

* congestion control
* packet fragmentation
* MTU discovery
* key rotation
* replay protection
* traffic padding
* adaptive path selection

---

✅ В результате получается **полноценная архитектура распределённого mesh-VPN**, которая объединяет:

* overlay routing
* multipath
* onion encryption
* NAT traversal
* transport camouflage

и функционально близка к современным overlay-сетям вроде Tailscale и ZeroTier, но с большей децентрализацией.
