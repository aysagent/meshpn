# P4 Wi-Fi authentication investigation — 26 October 2026

Status: **unresolved**. The confirmed defects below have been fixed; none is
claimed as the cause or a fix for the remaining `authentication_expired (2)`.
Final checkpoint: production restored and observed at 04:57 MSK. Native C6
SDK/rate/power comparisons remain unsuccessful. The physical-bus/USB-off
combination did not reach validated native association and is not counted.
This report supersedes earlier checkpoint statements about unavailable USB,
unflashed candidates and incomplete C6 backups.

## Scope and hardware

Only project P4 `E8F60AE395D0` and its on-board C6 `10BDA39E07C0` were programmed.
The Camic S3 was not touched. Mac Wi-Fi association and router settings were
not changed. Read-only Mac scans did not call association/disconnect APIs.
VPN was disabled for production Wi-Fi comparisons.

The Waveshare USB-C includes a **CH343P** UART bridge, serial `5B91063477`.
It is not a third external adapter. Manufacturer wiring establishes its P4
UART/reset connection; an esptool read verified the attached P4 eFuse MAC.
A targeted USB reset of this bridge recovered it from control-transfer timeouts
and enabled recovery without BOOT/RESET buttons. Before that recovery,
20 serial recovery attempts at 30-second intervals had already been made.
The earlier automatic-review ownership rejection was resolved with the
schematic and actual chip identity, rather than by opening an unidentified port.
[Waveshare schematic](https://files.waveshare.com/wiki/ESP32-P4-WIFI6/ESP32-P4-WIFI6-datasheet.pdf).

P4 GPIO6 is connected to C6 GPIO2. A temporary UART over this existing wire
provided native C6 logs and a verified flash-backup channel without soldering.
The P4 native USB and the CH343 bridge were kept distinct from the other board.

Two temporary diagnostic mistakes were also identified: a stop/deinit/init
sequence caused duplicate lwIP `netif_add`; a fatal `ESP_ERROR_CHECK` on an
unsupported HT40 request caused a boot loop in `auth_followup`. The latest
saved core confirms the latter. Neither experiment is in production firmware.
These failures do not establish a hardware fault.

## Confirmed code defects and retained fixes

### ESP-Hosted protocol queries

Pinned ESP-Hosted 1.4.7 dropped the AP interface selector in its generated
`get_protocol` request. The patch preserves it; independent STA/AP settings
were read back as 7/3 on hardware.

The installed IDF 5.4 C6 Wi-Fi archive also contains a protocol getter that
writes **two bytes through a `uint8_t *`**, while the pinned Hosted slave
allocates a one-byte temporary. Disassembly of the installed 5.5.5 archive
shows a byte write instead. Enlarging a P4 receive buffer cannot protect a
remote C6 stack. P4 skips these diagnostic RPCs on unverified/old C6 firmware;
the version gate permits an identified release with the documented workaround.
Native S3 queries use padded storage. Tests exercise a two-byte mock write and
the version boundary. See
[Espressif issue 17502](https://github.com/espressif/esp-idf/issues/17502) and
[Hosted changelog](https://github.com/espressif/esp-hosted-mcu/blob/main/docs/changelog.md).

The preserved working-night P4 ELF has no `esp_wifi_get_protocol` symbol, yet
that exact binary also failed when rolled back during this investigation.
The unsafe query is a real defect, but it does not explain all reproductions.

### Missing RPC responses

The generated `rpc_wifi_get_config` copied a missing response unconditionally;
`rpc_wifi_ap_get_sta_list` dereferenced one outside its guard. A harness compiled
from the real unmodified getter reproduced the null read under ASan. The patched
real functions handle missing replies and pass the corresponding tests.

### Concurrent synchronous RPC ownership and lifetime

A deterministic harness of the unmodified `get_response()` reproduced swapped
responses: caller B (UID 102) received UID 101 and caller A received UID 102.
Per-UID semaphores did not give ownership of entries in the shared FIFO.

The generated core now stores each synchronous reply in its transaction slot,
checks UID and response ID, and protects registration/publication/removal with
one mutex. Semaphore deletion follows slot removal, so a publisher cannot give
a deleted semaphore. Late, duplicate, orphaned and wrong-ID replies are freed.
UID allocation, table exhaustion, allocation failures and TX rejection are
covered. Round trips are not serialized behind a mutex held during waiting.

A local TX-failure reply now carries its request UID and is published after
TX cleanup. A failed-send log also used an already freed request; it now uses
the constant message ID. Existing asynchronous RPC and shutdown semantics were
not redesigned, so this is not a claim that the entire library is memory-safe.

Real-function tests include reverse caller scheduling, wrong/late/duplicate
replies, timeout/publication races, immediate wakeups, failed allocation/TX,
full tables, UID rollover and four callers with 4000 transactions. ASan/UBSan,
a separate TSan run, the complete host suite and the P4 build passed.

Retained fixes: `baee01c`, `b94dc39`, `d82220a`. The latter two include the
protocol safety gate, missing-reply handling and correlated RPC core. These
production changes were flashed and observed for 120 seconds: reason 2 remained.

## Completed Wi-Fi comparisons

Reason 2 is not proof of a wrong password. Native C6 logs now show an initial
`init -> auth (0xb0)`, followed about one second later by
`auth -> init (0x200)`, before association or DHCP. Espressif describes the
initial authentication timeout separately from the WPA key handshake.
[Wi-Fi driver reference](https://docs.espressif.com/projects/esp-idf/en/v5.4.4/esp32c6/api-guides/wifi.html).

| Comparison | Observed result / limit |
|---|---|
| Full P4 flash erase, stock firmware, user-entered profile | Still reason 2 |
| C6 Wi-Fi settings restore; EN reset; complete USB power removal | Still reason 2 |
| Rollback to saved working-night `97bb8d4-dirty` image | Still reason 2; no protocol-query symbol in its ELF |
| Production VPN disabled, healthy internal/DMA memory | Still reason 2; no matching SDIO I/O-error/drop evidence |
| P4 STA-only, APSTA, no profile-manager retry/scan loop | No association/IP |
| BGN HT20; supported BG/B requests; runtime power comparisons | No association/IP; accepted/read-back parameters distinguished from requests |
| Smaller buffers and SDIO 20 MHz versus 40 MHz | No association/IP |
| C6 station MAC changed to approved temporary LAA and restored | No association/IP; readbacks verified |
| Pinned BSSID/channel, derived hexadecimal PSK, power-save cycle, fast-connect clear, country US and restoration | Independent P4 STA-only no-DHCP test finished six phases with zero associations |
| Production with corrected synchronous RPC ownership | No association in 120-second observation |
| C6 PHY-calibration namespace erase via official API | Returned ESP_OK; original C6 still failed afterward |
| Temporary Hosted 1.4.7 app built with IDF 5.5.5, full calibration without cache | Native C6 still failed before association |
| P4 USB HS never initialized during first 30 seconds of association attempt | Still reason 2; native C6 logs captured after USB initialization |
| Native C6 management/control receive counters | Hundreds of target beacons, around −45 to −49 dBm; no own auth response/ACK observed |
| Ordinary raw probe requests | API accepted them; completion callbacks reported failure; other stations' ACK/probe traffic was received |
| Native IDF 5.5.5 C6 program, no Hosted/SDIO/NVS/AP/VPN | Three 35-second phases: original MAC reapplied, own P4 MAC, original restored; zero associations, reason 2 |
| Native IDF 5.4.1 C6 program, no Hosted/SDIO/NVS | Five 25-second phases also failed; original/own-P4 MAC and accepted runtime power request included |
| Native 5.5.5 radio-only variant, BT/802.15.4/software coexistence off, PHY limit 10 dBm | Three 20-second phases failed; documented pre-start b-rate disable returned ESP_OK; BGN/BG readbacks 7/3 verified |

The native C6 images received the saved profile over a CRC-checked private UART
packet **only into RAM**. No credentials were embedded in their firmware or
printed. The successful standalone run explicitly logged a valid 104-byte
packet and original-image selection at `0x10000`. Earlier standalone attempts
that failed the diagnostic UART handshake are **not** counted as Wi-Fi tests.
Initial NUL/noise broke the first readiness parser; framing was repaired before
collecting the native association results.

The attempted protocol bitmaps 6 (GN) and 2 (G) were accepted but read back as 7
(BGN); those attempts do not prove g-only operation. Espressif documents a
separate **pre-start** `esp_wifi_config_11b_rate()` call for disabling b rates.
That documented API is used in the subsequent radio-only/RF comparisons.
[Espressif protocol-mode guide](https://docs.espressif.com/projects/esp-idf/en/v5.3.1/esp32c6/api-guides/wifi.html).

The subsequent Hosted C6 RF sequence also reported failed raw-transmit
completions in AP mode on **channel 1**, after a successful AP start. The API
accepted the AP-frame send; a following sample showed its callback as failed.
This is not proof of an over-the-air failure mechanism. The attempted fixed
6 Mbit/s setting was made after start, outside the documented precondition;
that rate comparison is **not counted**. Tested sources/binaries and this limit
are frozen in `c6-fullcal/radio-v251-tested/`; the private source call order has
been corrected for any future trial, but the corrected rate test was not run.

The native 5.4 test also started a diagnostic AP. A read-only Mac scan returned
zero target results but **all 18 cached network names were redacted**, including
the current association identity. This negative scan cannot establish that C6
failed to transmit its AP. Mac channel remained 48 / 5 GHz; no association API
was called.

The previous saved TLS-crash and later diagnostic-crash stack segments each
contained one matching Wi-Fi credential candidate. Their SSID/password bytes
were identical. This is retained-stack evidence, not an old NVS backup or proof
of acceptance by the AP. Only comparison booleans are in the sanitized summary.

## C6 preservation, calibration and recovery

Three full **4 MiB** C6 flash backups were received with per-chunk/global CRC and
SHA-256 validation. Files were created with mode 0600, flushed and fsynced before
sending the physical acknowledgment. The first was backup-only; the second was
taken before the official PHY-namespace erase; the third was backup-only after
all radio trials. All three operations reported success,
and return to the original Hosted app was observed afterward.

Actual partition names/offsets: NVS `0x9000`, OTA data `0xd000`, PHY init
`0xf000`, original **`ota_0` at `0x10000`**, experimental `ota_1` at `0x190000`.
The original is a vendor app, not a partition named `factory`. Its description
is `network_adapter`, `release/ng-v1.0.2-330-g83efce6`, built with
`v5.4-dev-3602-ga97a7b0962` in October 2024. Temporary apps were written only
to the inactive slot. C6 bootloader, partition table and original app matched
between the first and final backups, including the complete 1.5 MiB original
application slot. The final comparison JSON records each region separately;
OTA data, experimental app and NVS are not claimed unchanged.

The backup-only helper does not initialize or erase NVS. The PHY-clear helper
waits for the verified backup acknowledgment, calls
`esp_phy_erase_cal_data_in_nvs()`, reports its result and returns. This is a
PHY-namespace reset, not a blanket C6 flash/NVS erase.
[Espressif RF calibration API](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32c6/api-guides/RF_calibration.html).

Temporary 5.5 apps prearm rollback by invalidating their own OTA entry after
verifying another bootable image. The 5.4 native helper uses its available OTA
API to verify/select the exact vendor original before Wi-Fi work. Diagnostic
timers also return to the original. No replacement C6 bootloader was flashed.

The six-byte stored PHY `cal_mac` prefix must not be compared directly with
the six-byte station MAC: the C6 default-MAC API exposes an EUI-64 form. The
observed cache prefix matches that form. It is not evidence of corrupt NVS.
The SDK cache caller's six-byte output allocation versus the EUI-64 API remains
a separate potential bounds defect; it is not claimed as this root cause.

## Evidence and remaining limits

Private artifacts are in ignored
`perf-results/p4-regression-2026-10-26-ibiahps3/`. They include flash images,
cores and profile-bearing memory, so raw files must not be committed or pasted.
Selected evidence:

- `c6-backup-before-phy{,-clear}.bin` and JSON/checksum/event sidecars;
- `c6-radio-{uart2,mgmt,usb-never-started,probe-tx}-trial.log`;
- `c6-standalone-native-mac-trial5.log` (valid native 5.5 comparison);
- `c6-standalone-sdk54-protocol-trial.log`, `c6-native54-ap-scan.txt`;
- `c6-native-radioonly-rate-trial.log`, `c6-final-rf-phase-trial.log`;
- `c6-native-quiet-bus-trial*.log` (count only a validated native run, not a failed UART setup);
- `followup/` for real RPC harnesses, cores and sanitized credential comparison;
- `isolated/` for the independent P4 test; `c6-standalone*`, `c6-fullcal/`,
  `p4-radio-trial/` and `p4-maintenance/` for isolated experimental sources.

The reproductions narrow the problem beyond the P4 VPN/admin/forwarding path,
but do not identify the radio hardware, AP, driver or RF environment as the
cause. Own-frame receive counters are not an independent air capture, and a
raw TX callback failure does not reveal its internal hardware failure reason.
The combined physical SDIO-pin/USB-off trial returned to Hosted before a
validated native profile exchange; both failed setup attempts are retained but
not counted as successful isolation or failed Wi-Fi association.

No router change, alternate network/computer requirement, Mac reassociation or
unproven permanent C6 replacement was used as a substitute for diagnosis.

## Final restoration checkpoint

Final C6 backup: `c6-backup-after-radio-trials.bin`, mode 0, CRC/SHA verified,
0600, acknowledgment after fsync, final result `mode=0 err=0`. The selected
original image offset is `0x10000`. The final comparison against the first backup
confirms identical bootloader, partition table, PHY-init and original OTA0 app.
See `c6-final-original-comparison.json`. The production P4 image was rebuilt and restored through the MAC-verified
flasher without buttons. USB product is again `MeshPN ESP32-P4 HS NCM`, build
`d82220a-dirty`, boot 1092. A 60-second observer recorded 29 samples, no reboot,
no successful Wi-Fi association, final reason 2, USB host ready and healthy
internal/DMA memory (approximately 99/59 KB free). VPN remains disabled for this
baseline. This is restoration of production software/admin access, **not**
restoration of internet connectivity. Final snapshots and logs are
`final-restored-{status.ndjson,logs.txt,summary.json}`.

Restored USB smoke test completed: warm-up plus one measured **8 MiB** local
HTTP response, measured 56.40 Mbit/s, queue-full delta
0. No restart was detected. This
is a short local USB recovery check, not a WAN/Wi-Fi throughput result. Files:
`final-usb-smoke/usb-local-NHiIlo/result.json` and its report.
