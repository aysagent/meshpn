# Waveshare ESP32-P4-WIFI6

Board profile: `waveshare_esp32_p4_wifi6` (`esp32p4`). It targets the
ESP32-P4NRW32 module (32 MiB flash, 32 MiB PSRAM), the on-board ESP32-C6 Wi-Fi
coprocessor over four-bit SDIO at 40 MHz, and the P4 USB 2.0 High-Speed device
controller.

## Connections

The two USB connectors have different jobs:

- USB-C / `USB-UART`: power, ROM download and UART0 logs through CH343P.
- Four-pin `USB`: USB 2.0 HS data for MeshPN NCM. The connector carries
  `VBUS`, `D-`, `D+`, `GND`; check the board silkscreen/schematic before making
  a cable. Do not infer the pin order from an ordinary USB header.

Flash through USB-C, then attach the four-pin USB data connector to the client.
They may be connected at the same time. The on-board power LED is wired to the
5 V rail, not a P4 GPIO, so the firmware cannot switch it off.

The P4 build gives the HS NCM function a per-board USB serial derived from its
Ethernet MAC. This keeps macOS from reusing the cached identity of an ESP32-S3
or another development board that used esp_tinyusb's default `123456` serial.
The NCM MAC string is populated before the controller starts enumeration.

## Build and flash

```bash
BOARD=waveshare_esp32_p4_wifi6 \
PORT=/dev/cu.wchusbserialXXXX \
./device/scripts/flash.sh ncm monitor
```

On Linux the programming port is normally `/dev/ttyUSB*`. If no port is found,
the command still builds the image. `setup-macos.sh` installs both the ESP32-S3
and ESP32-P4 toolchains.

The board profile selects the High-Speed root port. NCM telemetry and the
owned TX queue remain enabled; the ESP32-S3-only 64-byte double-FIFO experiment
and its DWC2 register telemetry remain disabled. HS NCM uses the TinyUSB HS
descriptors and 512-byte bulk endpoints.

At boot, `Using UTMI PHY instead of requested internal PHY` and the messages
about using default device/configuration descriptors are informational for the
ESP32-P4 HS controller and esp_tinyusb's Kconfig-generated descriptors. A
working host connection changes `usb host=0` to `usb host=1`. Persistent
`host=0` means USB enumeration has not completed; first verify the four-pin
connector's exact `VBUS`, `D-`, `D+`, `GND` order and inspect the host USB tree.
The USB-C programming connector carries UART/download traffic, not MeshPN NCM.

## ESP32-C6 firmware compatibility

The host build pins `esp_wifi_remote` to `0.14.*` and `esp_hosted` to `1.4.*`,
the ESP-IDF 5.x lane used by the vendor examples. The firmware already present
on the C6 must speak the matching ESP-Hosted protocol. A successful P4 build
does not prove that an arbitrary C6 slave image is compatible.

On first hardware boot, verify in UART logs that SDIO initializes and the C6 is
enumerated before diagnosing STA/AP behavior. If Hosted repeatedly resets or
times out, record the resolved `esp_hosted` version from `dependencies.lock.esp32p4`
and flash the C6 slave image shipped by that exact release. Then verify STA,
SoftAP, USB NCM, DHCP/DNS/NAT, reconnect and reboot.

If `MeshPN_<MAC suffix>` is absent from nearby Wi-Fi networks, keep using the
USB-C UART monitor; the four-pin USB data connector is not needed for SoftAP.
The P4 build logs `AP config start` and `AP radio start` after the C6 reports
`AP_START`, then repeats them every 30 seconds while AP is active. These lines
read the mode, SSID, hidden flag, configured and current channel, bandwidth,
country, security settings and AP MAC back from the C6 over ESP-Hosted. Query
failures are logged by API. `AP_STOP` is also logged. A successful `AP_START`
and clean readback still do not prove that the C6 is radiating beacons; a
nearby Wi-Fi scan is needed for that distinction.

Board references:

- [Waveshare board documentation](https://docs.waveshare.com/ESP32-P4-WIFI6)
- [Espressif USB device support for ESP32-P4](https://docs.espressif.com/projects/esp-usb/en/latest/esp32p4/usb_device.html)
