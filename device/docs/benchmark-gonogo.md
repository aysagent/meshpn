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
| Download | `curl -o /dev/null -w '%{speed_download}\n' https://speed.cloudflare.com/__down?bytes=10000000` | ≥ 5 Mbps | ______ |
| Upload | iperf3 server on LAN + client on phone/PC via dongle | ≥ 3 Mbps | ______ |
| Latency | `ping -c 20 1.1.1.1` via dongle | avg ms | ______ |

## Stability (30 min)

- [ ] DHCP survives USB unplug/replug
- [ ] iPhone resume from sleep recovers IP (NCM)
- [ ] WiFi reconnect after router reboot
- [ ] No watchdog resets in serial log

## Go / no-go for VPN phase 2

| Criterion | Pass? |
|-----------|-------|
| Internet works on iPhone USB-C | |
| Throughput acceptable for daily use | |
| Web UI provisioning reliable | |
| Willing to accept 2–8 Mbps with TLS VPN on S3 | |

**Decision:** GO / NO-GO / WAIT for Stamp-P4

## Notes

```
Date:
Board:
IDF version:
USB profile:
WiFi RSSI:
Observed download Mbps:
Issues:
```
