# Отладка производительности VPN

## Конфигурация метрик и логов

По умолчанию **периодический блок `PERFORMANCE METRICS` отключён** (меньше шума и нагрузки на GC). Счётчики `record*` по-прежнему накапливаются, если `metrics.enabled: true`.

Включить печать раз в `reportInterval` мс:

```json
"metrics": {
  "enabled": true,
  "periodicReport": true,
  "reportInterval": 5000
}
```

- **`trafficStatsIntervalMs`** (только client): интервал строки `[STATS]` в консоль. Значение **`0`** — отключить.
- **`debugTransport: true`**: раз в `debugTransportIntervalMs` (по умолчанию 2000) лог `rss`, `heapUsed`, очереди `WorkerPipeline`, `bufferedAmount` / очереди send-buffer / overflow WebRTC.
- **`webrtc`** (объект в конфиге ноды): опционально `sendBufferMaxQueue`, `sendOverflowMax`, `sctp` — см. раздел «План B» ниже.

## Запуск с метриками (periodicReport: true)

При `metrics.periodicReport: true` каждые `reportInterval` мс выводится отчёт:

```
========== PERFORMANCE METRICS ==========
Elapsed: 5.0s

--- THROUGHPUT ---
TUN Read:      1.25 Mbit/s (150 pkts)
WebRTC Send:   1.87 Mbit/s (150 pkts, 0 failed)
WebRTC Recv:   0.85 Mbit/s (95 pkts)
Responses:     0.65 Mbit/s

--- SIZE EXPANSION ---
Onion:         1.47x
Serialize:     1.08x

--- TIMING (avg ms) ---
Onion Encrypt: 0.150 ms
Onion Decrypt: 0.120 ms
Serialize:     0.050 ms
Deserialize:   0.030 ms
NAT Process:   0.200 ms

--- TOTALS ---
TCP Connections: 5
TCP Data: sent 125.50 KB, recv 450.00 KB
Errors: 0
==========================================
```

## Интерпретация метрик

### Throughput
- **TUN Read** — скорость чтения из TUN интерфейса (то что приходит от приложений)
- **WebRTC Send** — скорость отправки через WebRTC (включая overhead)
- **WebRTC Recv** — скорость получения через WebRTC
- **Responses** — скорость отправки ответов

### Size Expansion
- **Onion** — коэффициент увеличения размера после onion encryption
  - 1.47x означает +47% overhead (нормально для JSON+base64)
- **Serialize** — коэффициент увеличения после сериализации пакета
  - 1.08x означает +8% overhead от метаданных

### Timing
- Все значения в миллисекундах
- Если какое-то время > 1ms — это потенциальная проблема
- NAT Process включает DNS lookup и установку соединения

## Тест raw WebRTC

Для проверки чистой скорости WebRTC канала без VPN overhead:

**На exit сервере:**
```bash
node scripts/test-webrtc-throughput.js server
```

**На client машине:**
```bash
node scripts/test-webrtc-throughput.js client <exit-server-ip>
```

Ожидаемые результаты:
- Через TURN relay: 5-20 Mbit/s
- Напрямую (если NAT traversal работает): 50-100+ Mbit/s

## Диагностика проблем

### Проблема: TUN Read высокий, WebRTC Send низкий
**Причина:** Bottleneck в encryption или serialization
**Проверка:** Смотри timing для Onion Encrypt и Serialize

### Проблема: WebRTC Send высокий, WebRTC Recv низкий
**Причина:** Потеря пакетов в сети или на TURN
**Проверка:** Запусти raw WebRTC тест

### Проблема: WebRTC Recv высокий, Responses низкий
**Причина:** Bottleneck в NAT processing
**Проверка:** Смотри timing для NAT Process

### Проблема: Onion expansion > 1.5x
**Причина:** JSON+base64 overhead слишком большой
**Решение:** Переключиться на бинарный формат onion

### Проблема: Много TCP Connections
**Причина:** Соединения не переиспользуются или есть retransmissions
**Проверка:** Смотри логи curl с -v флагом

### Проблема: WebRTC Send failed > 0
**Причина:** Переполнение буфера WebRTC
**Решение:** Уменьшить скорость отправки, добавить backpressure

### Проблема: iperf3 `-R` после повторного запуска падает до 0 Mbit/s или `iperf3: Cannot allocate memory`

**На стенде:** проверить `free -h`, swap; не утрамбовывать client, exit и iperf3 на одной маленькой VM без запаса RAM.

**В коде / конфиге (план B при нестабильности):**

1. **`dcMode: "reliable"`** (вместо `performance`) на client и exit — ordered/reliable DataChannel, меньше потерь при перегрузке.
2. **`workers.txPool: 1`** на exit — уже безопаснее вместе с очередью per-client; сужает параллелизм TX.
3. **Уменьшить SCTP-буферы** (меньше пиковая память процесса), в конфиге ноды:

```json
"webrtc": {
  "sctp": {
    "recvBufferSize": 1048576,
    "sendBufferSize": 1048576,
    "maxChunksOnQueue": 4096
  }
}
```

(поля совпадают с `setSctpSettings` в node-datachannel; применяются при создании `WebRTCTransport`.)

4. Включить **`debugTransport: true`** и смотреть рост `overflowQueued`, `overflowDroppedTotal`, `txP`/`rxP` у pipeline.

## Быстрая диагностика

1. Запусти VPN и curl большой файл
2. Смотри метрики
3. Определи какой показатель самый низкий — это bottleneck
4. Если raw WebRTC тест показывает хорошую скорость, а VPN — плохую, проблема в нашем коде
5. Если raw WebRTC тоже медленный — проблема в сети/TURN
