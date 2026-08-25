# MeshVPN device — benchmark & go/no-go checklist

Run after flashing stage-1 firmware (`./device/scripts/flash.sh`).

## Setup

1. Connect XIAO ESP32-S3 to host via USB-C.
2. If WiFi not configured: join SoftAP `MeshVPN-Setup`, open `http://192.168.4.1/login`, password `admin`.
3. Scan WiFi, save home router credentials.
4. Verify host gets IP on USB Ethernet (`192.168.7.x`).

## Throughput tests

| Test | Tool | Target | Record |
|------|------|--------|--------|
| Download | `curl -o /dev/null -w '%{speed_download}\n' https://speed.cloudflare.com/__down?bytes=10000000` | ≥ 8 Mbps (floor 5) | ______ |
| Upload | iperf3 server on LAN + client on phone/PC via dongle | ≥ 5 Mbps (floor 3) | ______ |
| Latency | `ping -c 20 1.1.1.1` via dongle | avg ms | ______ |

Also compare the same download test on the phone over the **same WiFi without the dongle**. If that is already &lt; 10 Mbps, USB tuning will not help much.

Hard ceiling on this board: USB Full-Speed (~12 Mbps raw) → useful NAT throughput typically **8–10 Mbps**.

## Recorded results

### Baseline (before throughput tune, Aug 2026)

| Direction | Mbps | Notes |
|-----------|------|-------|
| Download | ~5.6 | iPhone USB NCM → WiFi NAT, after MAC uniqueness fix |
| Upload | ~4 | same path |
| Ethernet | stable | duplicate STA/NCM MAC was the flap root cause |

### After throughput tune (`lwip` windows + NCM NTB + STA PS off + TX retry restored)

| Direction | Mbps | Notes |
|-----------|------|-------|
| Download | **7.2** | iPhone USB NCM, Aug 2026 |
| Upload | **4.9** | |
| `usb.tx_dropped` | **661** | after speedtest; was **2396** with single-shot TX (bad) |
| Ethernet / admin | OK | MAC fix retained, `192.168.7.1` works |

Plan target was ≥8 / ≥5 — close to FS USB ceiling (~8–10 useful). Further TX tuning risks regressing stability.

### Phase 1 — tcpip CPU0 + LWIP IRAM optimization (Aug 2026)

Commit: `ae137fd`.

| Direction | Mbps | Δ vs 7.2/4.9 | tx_dropped | tx_retried | Ethernet |
|-----------|------|--------------|------------|------------|----------|
| Download  | **~7.5** | +0.3 | **433** (was 661 cumul.) | 3485 | OK |
| Upload    | **~6.0** | **+1.1** | | | OK |

Decision: **KEEP** — upload crossed plan floor (≥5); download trending toward 8.

### Phase 2 — TinyUSB prio 9 + tcpip prio 18 (Aug 2026)

Commit: `2ebfb4d` → **REVERTED** (TinyUSB 9→6).

Speed-test page barely loaded / never finished — TinyUSB prio 9 likely starved WiFi/tcpip.

| Direction | Mbps | Notes |
|-----------|------|-------|
| Download  | — | page failed to load |
| Upload    | — | |

Decision: **REVERT** TinyUSB priority; removed explicit `LWIP_TCPIP_TASK_PRIO=18` (was IDF default anyway — verified on Phase 1 build).

### Phase 3a — TCP_SND_BUF 32768 (WND stays 16320) (Aug 2026)

| Direction | Mbps | Δ vs 7.5/6.0 | tx_dropped | tx_retried | Ethernet |
|-----------|------|--------------|------------|------------|----------|
| Download  | **~7.5** | 0 | | | OK |
| Upload    | **~6.0** | 0 | | | OK |

Decision: **KEEP** — no measurable gain; no regression vs Phase 1.

### Phase 3b — WiFi buffer pool + AMPDU windows (Aug 2026)

| Direction | Mbps | Δ vs 7.5/6.0 | tx_dropped | tx_retried | Ethernet |
|-----------|------|--------------|------------|------------|----------|
| Download  | ______ | | | | |
| Upload    | ______ | | | | |

Decision: KEEP / REVERT.

### After CDC console off + no per-second DHCP refresh (Aug 2026)

| Direction | Mbps | Notes |
|-----------|------|-------|
| Download | ______ | fill after flash + speedtest |
| Upload | ______ | |
| `usb.tx_dropped` | ______ | delta vs previous 661 |
| `usb.tx_retried` | ______ | delta vs previous 2996 |
| Ethernet / admin | | `192.168.7.1/login` |

## Stability (30 min)

- [ ] DHCP survives USB unplug/replug
- [ ] iPhone resume from sleep recovers IP (NCM)
- [ ] WiFi reconnect after router reboot
- [ ] No watchdog resets / Ethernet flap
- [ ] `http://192.168.7.1/login` still works

## Go / no-go for VPN phase 2

| Criterion | Pass? |
|-----------|-------|
| Internet works on iPhone USB-C | |
| Throughput acceptable for daily use (≥8/5 preferred) | |
| Web UI provisioning reliable | |
| Willing to accept 2–8 Mbps with TLS VPN on S3 | |

**Decision:** GO / NO-GO / WAIT for Stamp-P4

## Notes

```
Date:
Board: XIAO ESP32-S3
IDF version:
USB profile: ncm
WiFi RSSI:
Observed download Mbps:
Observed upload Mbps:
Issues:
```
