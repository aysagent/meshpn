# clean-vpn transport tests

E2E smoke: каждый `--type` поднимает TUN client↔exit и пропускает IPv4 **c2e** (client→exit) и **e2c** (exit→client) без `--split-default`.

## Требования

| | Linux | macOS |
|--|-------|-------|
| TUN | `npm run build:tun-linux` | `cd helpers && make` (utun-helper) |
| Запуск | `sudo` | `sudo` |
| Probes | `ping -I tunX`, `curl --interface tunX` | `ping -I utunX`, `curl --interface utunX` |

Env для client в harness: `CLEAN_VPN_SKIP_CLIENT_ROUTES=1` (системный split/bypass не трогаем).

## Быстрый старт

```bash
# macOS
cd helpers && make
sudo env PATH=$PATH node scripts/clean-vpn/tests/run.mjs --tier=1

# Linux CI
sudo env PATH=$PATH node scripts/clean-vpn/tests/run.mjs --tier=1 --tier-max=2 --json /tmp/report.json
```

npm:

```bash
sudo env PATH=$PATH npm run test:clean-vpn-transports
sudo env PATH=$PATH npm run test:clean-vpn-transports:tier2
```

## CLI

```bash
sudo env PATH=$PATH node scripts/clean-vpn/tests/run.mjs \
  --tier=1 [--tier-max=3] \
  [--transport=socket] [--variant=base|all] \
  [--topology=exit-listens|client-listens|both] \
  [--suite=smoke|boring-profile] \
  [--turn=1.2.3.4:5678] \
  [--verbose] [--json report.json]
```

- **`--turn=IP:PORT`** — включает WebRTC relay-кейсы (нужен coturn); без флага relay skip.
- **`SKIP_TIER3=1`** — без webrtc/chrome/punch topologies.
- **transparent/combo** — всегда `--tunnel-peer=127.0.0.1:9` (без iptables REDIRECT).

## Матрица (кратко)

| Tier | Транспорты |
|------|------------|
| 1 | socket, http, websocket (exit-listens) |
| 2 | udp, tls, boring-tls, quic-ext, transparent-tls, combo-tls |
| 3 | websocket client-listens, webrtc (direct + optional relay) |

Probes: HTTP на `10.99.0.1:18080` и `10.99.0.2:18081` через соответствующий TUN.

## Route guard

После spawn client+exit harness проверяет, что не появились split-default маршруты (`0.0.0.0/1`) и iptables `clean-vpn-ttl` (Linux).

## Связанные тесты

| Скрипт | Назначение |
|--------|------------|
| `scripts/test-transparent-tls-enc-sni.mjs` | enc-SNI wire/crypto unit |
| `scripts/test-boring-tls-smoke.mjs` | boring-tls-helper unit |
| **этот harness** | transport E2E + TUN |

## Разработка на macOS

clean-vpn использует [`scripts/lib/clean-vpn-platform/`](../../lib/clean-vpn-platform/) — utun-helper, `ifconfig`, NAT no-op для transport smoke. iptables REDIRECT только Linux.

Legacy doc: [../../clean-vpn-transports-test.md](../../clean-vpn-transports-test.md).
