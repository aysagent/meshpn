# SPDX-License-Identifier: MIT

This folder contains the ESP-IDF firmware for the MeshVPN USB WiFi dongle.

## Quick start (macOS)

```bash
./device/scripts/setup-macos.sh   # once
source ~/.zshrc
./device/scripts/flash.sh         # build + flash (NCM / iPhone)
```

See [docs/xiao-esp32s3.md](docs/xiao-esp32s3.md) for hardware notes.

## Credentials (defaults)

| What | Value |
|------|--------|
| Setup WiFi (SoftAP) SSID | `MeshVPN-Setup` |
| Setup WiFi password | `meshvpn123` |
| Web admin login | `admin` |

The SoftAP stays up permanently, also after WiFi is provisioned, so the device
is always reachable even with wrong credentials or a dead uplink.

- **Over WiFi:** join `MeshVPN-Setup`, open `http://192.168.4.1/login`
- **Over USB (iPhone/PC):** open `http://192.168.7.1/login`

If the USB address does not answer, the **Status** section of the web UI shows
what the USB link is doing (`usb` in `/api/status`):

| Field | Meaning |
|-------|---------|
| `host_ready: false` | the host never configured the device — wrong USB class for this host, cable without data lines, or the host does not support the profile |
| `tx_ok` climbing | the device is answering; a stuck page is then a host-side routing issue |
| `tx_dropped` climbing | the host is not draining the USB IN endpoint |
| `tx_no_host` climbing | frames queued with no host attached |

`ncm` suits iPhone and modern macOS, `ecm` Linux and older macOS, `rndis`
Windows. Reflash with a different profile via `USB_PROFILE=ecm ./device/scripts/flash.sh`.

## Recovery

- **Factory reset:** hold the **BOOT** button for 5 seconds while the device is
  running. All settings are erased and the device reboots.
- **Device log:** the NCM firmware takes over USB, so there is no serial
  console. The last ~12 KB of log is available in the web UI ("Logs") or at
  `GET /api/logs`.
- **Reflashing:** hold **BOOT**, plug in USB, release, then run `flash.sh`.
