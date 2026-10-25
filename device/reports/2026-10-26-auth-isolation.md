# P4 authentication failure: application isolation, 26 October 2026

Status: unresolved; no root-cause fix claimed.

After the complete P4 erase and C6 Wi-Fi settings restore, the user re-entered
the Wi-Fi profile and still received reason 2. Baseline: `c8b4c8c`, boot 1,
VPN disabled, about 99 KB internal free memory, no recorded SDIO I/O errors
or RX drops. C6 firmware itself has not been replaced.

## On-device experiment

Only bound P4 `E8F60AE395D0` was programmed. Mac Wi-Fi was unchanged.
Temporary firmware `47d8764-dirty`, boot 2, replaced the profile manager loop
with two sequential single connection attempts:

1. Stop Wi-Fi, select STA only, explicitly allow b/g/n with HT20, apply the
   existing saved credentials, start and connect once. Observe for 45 seconds.
2. Stop Wi-Fi, select APSTA, set both interfaces to b/g/n HT20, apply the same
   credentials, start and connect once. Observe for 45 seconds.

Both returned ESP_OK from the connect request, but neither obtained an IP;
reason 2 appeared within five seconds and persisted. AP was off in the first
phase and on in the second. No profile-manager rescans/reconnects or radio
sampling ran during these attempts. Initial normal bridge setup still ran
before the experiment; this is not a standalone replacement C6 firmware.

In each phase `esp_wifi_get_config()` returned ESP_OK and exact byte matches
for the configured SSID and password. Only comparison booleans were logged,
not credentials. This verifies transfer/readback, not that the AP accepts
those credentials. Reason 2 can indicate initial authentication timeout or
an AP-supplied reason, rather than proving a password mismatch:
[Espressif Wi-Fi driver documentation](https://docs.espressif.com/projects/esp-idf/en/v5.4.4/esp32c6/api-guides/wifi.html).

## Interpretation and restoration

The failure reproduces without the application's connection-management loop,
without concurrent AP operation and with legacy protocols selected for the
attempt. This narrows the investigation but does not exonerate all host code,
the installed C6 firmware, or identify the router as the cause.

A further temporary C6 station-MAC comparison image was prepared, but automated
approval review rejected flashing it without explicit consent to that side
effect. It was **not flashed**; the user was asked separately. No MAC change
was applied. The candidate is kept only in ignored local artifacts.

Temporary source changes were removed, production firmware rebuilt and
reflashed. USB admin returned; boot 3 has AP active, saved profile 1, VPN OFF,
and STA still reporting reason 2. The build string retained `47d8764-dirty`
from the diagnostic CMake configuration; the restored source and application
manager are the production implementation. No further erase was performed.

Local evidence: `perf-results/auth-isolation-2026-10-26-o21gwf7e/` contains
sanitized status, experiment markers and restored status. Flash/build consoles
are `/tmp/meshpn-auth-isolation-*.log` and `/tmp/meshpn-auth-stock-*.log`.

Next: obtain consent before the station-MAC comparison; if it does not separate
the failure, test the board against a second AP without switching Mac Wi-Fi.
Keep TLS load testing pending until DIRECT connectivity is restored.
