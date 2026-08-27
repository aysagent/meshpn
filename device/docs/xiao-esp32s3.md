# Seeed XIAO ESP32-S3 — meshvpn dongle hardware notes

## Board

- SoC: ESP32-S3R8 (dual-core 240 MHz)
- Flash: 8 MB, PSRAM: 8 MB
- WiFi: 2.4 GHz 802.11 b/g/n
- USB: single USB-C (OTG full-speed, shared with USB-Serial-JTAG)

## Pinout (meshvpn defaults)

| Function | Pin |
|----------|-----|
| User LED | GPIO21 (active low) |
| UART TX (debug) | GPIO43 (D6) |
| UART RX (debug) | GPIO44 (D7) |
| BOOT button | GPIO0 |

## Flashing

1. First flash: connect USB-C, optionally hold **BOOT** while plugging in.
2. Run from repo root:

```bash
./device/scripts/flash.sh
```

3. After NCM firmware is running, the USB serial console may disappear. Reflash:
   - Hold **BOOT**, plug USB, release **BOOT**, run `flash.sh` again.
   - Or use UART on D6/D7 with `./device/scripts/monitor.sh`.

## USB profiles

| Profile | Command | Host |
|---------|---------|------|
| NCM (default) | `./device/scripts/flash.sh` | iPhone USB-C, modern macOS |
| RNDIS | `./device/scripts/flash.sh rndis` | Windows |
| ECM | `./device/scripts/flash.sh ecm` | Linux, legacy macOS |

## Network layout

Both LANs are iot-bridge data-forwarding interfaces, so each gets its own DHCP
server, NAT and DNS handed down from the WiFi uplink.

| Interface | Subnet | Address |
|-----------|--------|---------|
| USB host LAN (clean-vpn `--client-lan-subnet`) | `192.168.7.0/24` | `192.168.7.1` |
| SoftAP `MeshVPN-Setup` (always on) | `192.168.4.0/24` | `192.168.4.1` |
| WiFi station uplink | DHCP from router | — |

Both LAN addresses are pinned: the bridge is not allowed to relocate them if
the router happens to use the same subnet, because a silently moved address
would be unreachable. Avoid `192.168.4.0/24` and `192.168.7.0/24` on the router.

Web UI: `http://192.168.4.1/login` or `http://192.168.7.1/login`, password `admin`.

## iPhone notes

- Requires USB-C iPhone (NCM).
- USB link is raised when the host enumerates the device (NCM); WiFi uplink is not required for the web UI.
- After reflash: renew DHCP on iPhone (Settings → Ethernet → renew lease) or unplug/replug USB.

## Debugging without a serial console

NCM claims the USB peripheral, so USB-Serial-JTAG logging stops once the app
runs. Instead:

- Web UI → **Logs**, or `curl -H "Authorization: Bearer $TOKEN" http://192.168.4.1/api/logs`
- LED on GPIO21: solid = WiFi uplink up, blinking = no uplink
- `/api/status` reports the real USB/SoftAP addresses and the last WiFi
  disconnect reason code (`201` = AP not found, `15` = wrong password)
- UART on D6/D7 with `./device/scripts/monitor.sh` if a USB-UART adapter is available

The first log line of every boot is the post-mortem of the previous run:

```
W meshvpn_log: boot #12, last reset: PANIC
E meshvpn_log: last crash in task 'tiT' pc=0x420... cause=29 vaddr=0x00000000
E meshvpn_log: backtrace: 0x420... 0x420... ...
```

A boot counter that keeps climbing means the device is rebooting. `PANIC`,
`interrupt watchdog` and `task watchdog` come with a core dump summary (task,
PC, backtrace); `BROWNOUT (power supply)` means the USB host cannot supply the
WiFi TX current spike — the XIAO build disables the brownout detector for
bus-powered use; if you still see BROWNOUT, try a powered hub or a different port.

Resolve a backtrace address to a source line with:

```bash
xtensa-esp32s3-elf-addr2line -pfiaC -e device/build/meshvpn_device.elf 0x420...
```

## USB descriptor compliance (iOS)

iOS binds its Ethernet stack to **CDC-NCM** only — ECM and RNDIS do not work —
and it is strict about descriptor compliance. `TUD_CDC_NCM_DESCRIPTOR` opens
with an Interface Association Descriptor, so the USB spec requires the device
descriptor to advertise class `EF` / subclass `02` / protocol `01`.
`esp_tinyusb` only emits that triple when `CFG_TUD_CDC` is non-zero; with NCM
alone it reports class `0x00`, and iOS then never creates the interface.

The NCM profile therefore enables CDC-ACM next to NCM. The ACM interface is
also claimed as the console, so `idf.py monitor` works over the same cable
(`/dev/cu.usbmodem*`) while the network interface is up.

## USB transmit path

`iot_bridge` hands every outgoing frame to `tinyusb_net_send_sync()` with
`portMAX_DELAY` and drops it if the NCM/ECM IN endpoint is still busy with the
previous frame. A lone packet such as a DHCP reply gets through, but a stream of
TCP segments — the web UI, for instance — mostly does not, which looks exactly
like "the USB address does not respond". The infinite timeout is a second
hazard: `tinyusb_net_send_sync()` can miss its completion flag, and it is called
from the TCP/IP thread, so that would wedge all networking.

`meshvpn_usb_attach_netif()` therefore replaces the transmit callbacks on the
bridge's USB netif (`esp_netif_set_driver_config`) with a bounded, retrying
version, and counts the outcomes into `/api/status`.

Testing the USB side from macOS is easier than from an iPhone (NCM is supported
natively): plug the dongle in and check

```bash
ifconfig | grep -B4 '192.168.7'      # host should get 192.168.7.2
ping -c3 192.168.7.1
curl -sS -o /dev/null -w '%{http_code}\n' http://192.168.7.1/login
```

## Limitations (prototype)

- USB full-speed → expect ~5–12 Mbps throughput.
- VPN phase 2 supports only `clean-vpn --type=tls` (not boring/combo/transparent).
