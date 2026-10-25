# P4 factory reset — 26 October 2026

User explicitly requested complete erase/reflash of the P4 and a C6 reset after
Wi-Fi continued reporting `authentication_expired` with newly entered credentials.

## Performed

- Prepared and preserved the stock `c8b4c8c` firmware before erasing anything.
- Flashed a temporary P4 recovery image, called `esp_wifi_restore()` on C6,
  and verified the log marker `C6_FACTORY_WIFI_RESTORE result=ESP_OK code=0`.
- Reverted the temporary source change; it is absent from the final image.
- Verified P4 eFuse MAC `E8F60AE395D0`, then used the same open ROM connection
  for `write_flash --erase-all --flash_size 32MB` and the stock image.
  Esptool reported successful chip erase in 13.3 seconds. All written-image
  hashes verified. The application USB CDC returned automatically.
- Other connected devices and Mac Wi-Fi were untouched. No old configuration
  was restored after the erase.

## Verified after reset

| Item | Result |
|---|---|
| Firmware | `c8b4c8c` |
| Boot count | 1 |
| Saved Wi-Fi profiles | 0; setup mode enabled |
| VPN | disabled; endpoint empty |
| WireGuard private key / PSK | absent / absent |
| USB host | ready |
| USB / AP gateways | `192.168.10.1` / `192.168.11.1` |
| STA / AP configured bandwidth | 20 / 20 MHz |
| AP | active |
| USB admin | HTTP; default password `admin` verified |

The user can now enter Wi-Fi credentials again. STA connectivity, DIRECT
internet and TLS load acceptance are not claimed by this reset check.

## C6 scope

C6 **Wi-Fi settings** were reset through its running firmware. Its whole flash,
bootloader and factory radio firmware were not erased or reflashed. With the
current cables both USB paths terminate at P4. Waveshare's documented full C6
flashing path requires the C6 UART pads and IO9 held low during power-up:
[manufacturer FAQ](https://docs.waveshare.com/ESP32-P4-WIFI6/FAQ).
The installed ESP-Hosted OTA path updates an application partition, not the
entire C6 flash, so it is not an equivalent complete erase/recovery operation.

Local evidence (ignored by Git):
`perf-results/factory-reset-2026-10-26-jnmoq5ie/` contains the preserved stock
artifacts, C6 reset confirmation and sanitized `after-reset.json`.
The full erase/write console log is `/tmp/meshpn-p4-erase-reflash.log`.
