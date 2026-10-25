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

## Approved station-MAC comparison

The user explicitly approved the temporary C6 STA MAC change and restoration.
A second diagnostic image (`268cc3c-dirty`, boot 4) made two single STA-only
b/g/n HT20 attempts, each observed for 45 seconds:

| Phase | C6 STA MAC readback | Result |
|---|---|---|
| Temporary locally administered address | `12:bd:a3:9e:07:c0` | No IP; reason 2 |
| Restored original address | `10:bd:a3:9e:07:c0` | No IP; reason 2 |

The driver readback matched the requested MAC in both phases; the second also
matched the original address captured before the experiment. SSID/password
readback matched in both phases. Configured maximum TX power readback was 80
quarter-dBm (20 dBm); this is not a measurement of actual RF output.
No HTTP probe was attempted because neither phase obtained a DHCP address.

The changed address did not restore authentication. This does not support an
explanation limited to router state for the original MAC; it does not establish
the underlying cause. The host polling session was interrupted by a separate
admin login; log markers retained on the device recovered the missing interval.

Evidence: `mac-status.ndjson` and `mac-isolation.log` in the same ignored artifact
directory. Production source contains no diagnostic changes. Mac Wi-Fi and the
USB Ethernet identity were unchanged throughout.
After the experiment, the clean production implementation was flashed back:
boot 5, build label `268cc3c-dirty` (cached at diagnostic configuration time),
USB admin/host ready, AP active, saved profile 1 retained, VPN OFF, normal
manager scanning and still reporting reason 2. The restored binary contains
no `AUTH_ISOLATION` markers. Evidence: `mac-restored-stock.json` and
`/tmp/meshpn-auth-mac-restore-flash.log`.

## Overnight regression investigation

The user requested investigation of our regression without changing the router
or switching Mac Wi-Fi. Only bound P4 was flashed; C6 firmware was not replaced.
All following attempts had VPN disabled and retained the saved Wi-Fi profile.

| Experiment | Verified condition | Result |
|---|---|---|
| Actual saved working-night image `97bb8d4-dirty` | Original binary, not a rebuild; previously measured 34.35–37.67 Mbit/s | 150 s observation, repeated reason 2, no IPv4 |
| C6 Wi-Fi init with `nvs_enable=0` | Host init setting changed; PHY calibration storage is separate | 120 s, reason 2 |
| STA only from initial startup | AP never started, normal connection manager disabled; power save disabled before connect | No association/IP |
| Legacy b/g and b-only | Protocol readbacks 3 and 1 respectively | Both reason 2 |
| Lower configured TX power | Readbacks 32 then 80 quarter-dBm | Neither restored association |
| Conservative C6 buffers | Static RX 10, dynamic RX/TX 32, RX BA window 6 | Reason 2 |
| Post-start b/g/n HT40 | Protocol 7 and bandwidth HT40 confirmed | Reason 2 |
| SDIO 20 MHz | Driver startup confirms 20000 KHz, original buffers | Reason 2 |
| APSTA with differing protocol masks | STA 7 / AP 3 independently read back after RPC fix | Reason 2 |

The saved working-night application SHA-256 is
`76649752acdd098944ce9fc3cd6a76f634afb37b6e67f1a20d7249e4f6a52950`.
Its failure now means reverting recent P4 application changes alone did not
restore connectivity. It does **not** prove that prior software changes had no
persistent effect, nor identify the router or hardware as the cause.

Important limitations of attempted settings:

- Requesting b/g/n before start sometimes returned protocol `0x47` or retained
  the previous protocol. ESP_OK alone did not establish the requested mode.
  Only confirmed readbacks above are treated as valid comparisons.
- Requesting PMF incapable read back as capable. This was **not** a successful
  PMF-disabled test.
- Setting a manual RU country returned ESP_ERR_INVALID_ARG. The initial country
  was `01`, channels 1–11, automatic policy. No regional A/B conclusion follows.
- Configured power is not a measurement of RF output. A Mac network-list snapshot
  did not show MeshPN, but a cached scan cannot establish absence of beacons.

### Diagnostic restart failure

A temporary stop/deinit/init experiment caused a separate P4 panic. The saved
core, decoded against its exact diagnostic ELF, reports
`assert failed: netif_add ... (netif already added)` in task `tiT`, through
`esp_netif_start_api`. It is a duplicate network-interface registration during
the experiment, not evidence of the original authentication cause or the older
TLS heap-corruption crash. This recovery approach was removed; it is not part
of the production code. The diagnostic image restarted repeatedly before its
replacement. Core and matching ELF are retained locally.

### Confirmed code defect and retained changes

ESP-Hosted 1.4.7 `rpc_wifi_get_protocol()` omitted the interface argument, so
AP protocol queries actually requested STA. The build now patches a generated
copy, leaving managed sources intact. A test compiles the real getter against
different STA/AP responses, checks errors/null output, and rejects an unknown
dependency shape. Hardware confirmed STA 7 and AP 3 after the fix. This corrects
diagnostics; it did **not** fix authentication. Previous independent AP AX
readback claims must be qualified accordingly.

Status now distinguishes 802.11 association from IPv4 acquisition and records
association/disconnect counts, disconnect RSSI and age. Event logs include the
reason and channel without credentials or additional remote RPCs. Restored
production boot 16 reports zero association events while disconnect events
increase with reason 2, around 99 KB internal and 59 KB DMA free. USB admin and
AP configuration remain available, VPN is OFF, SDIO is back at 40 MHz, and the
original C6 MAC/profile are retained. All temporary experiment branches were
removed. P4 and XIAO builds and the complete host suite passed; XIAO was not
flashed.

### Internet research and remaining boundary

Espressif documents a separate PHY calibration namespace and the C6-side
`esp_phy_erase_cal_data_in_nvs()` API before Wi-Fi initialization:
[C6 RF calibration](https://docs.espressif.com/projects/esp-idf/en/v5.5.5/esp32c6/api-guides/RF_calibration.html).
The P4 erase and Wi-Fi restore performed earlier are not proof that C6 PHY
calibration was erased. The installed remote RPC interface exposes no equivalent
calibration-erasure or raw C6 flash-backup operation.

An upstream fix addresses an RF power-state flag preventing station connection
under enhanced light sleep:
[Espressif commit 74dc204](https://github.com/espressif/esp-idf/commit/74dc204).
It affects radio-side code, not merely the P4 host SDK. Installed factory C6
firmware version is unknown, so applicability is unproven; disabling power save
in our comparison did not restore connection. This is a lead, not a diagnosis.

Further useful evidence needs C6-side logs/firmware identification or an
independent capture of authentication management frames. A C6 firmware/calibration
experiment needs a verified recovery path and factory backup first. The current
two USB connections do not expose C6 UART; blindly replacing its only reachable
firmware over SDIO would risk losing that access. No such update was attempted.
The cause remains unresolved. DIRECT and TLS load tests remain blocked.

Local evidence: `perf-results/p4-regression-2026-10-26-ibiahps3/` contains per-test
status/logs, saved images and the diagnostic core. These ignored files may contain
sensitive memory/network data and are not committed. Build/test/flash consoles:
`/tmp/meshpn-regression-*.log`, `/tmp/meshpn-restored-flash.log` and
`/tmp/meshpn-country-core-decoded.log`.

## Continued investigation after the initial report

The user requested continued investigation rather than stopping at the missing
C6 diagnostics. New findings below do not establish an authentication fix.

### Unsafe protocol query on an unverified C6

The installed ESP-IDF 5.4 C6 archive's `wifi_get_protocol_process` was inspected
with the RISC-V disassembler. It uses `sh` (a 16-bit store) for the output of the
public `uint8_t *` getter. ESP-Hosted 1.4.7's slave handler instead allocates a
single `uint8_t protocol_bitmap`. The installed 5.5.5 C6 archive uses `sb`
(an 8-bit store). This is a concrete compatibility hazard, though the SDK in
the board's factory C6 firmware remains unknown.

Espressif tracks the output-width bug as
[IDFGH-16362 / issue 17502](https://github.com/espressif/esp-idf/issues/17502),
and lists a slave-side workaround in
[ESP-Hosted 2.6.6](https://github.com/espressif/esp-hosted-mcu/blob/main/docs/changelog.md).
An enlarged output buffer on **P4** cannot protect the **C6** stack, where
the native getter executes.

Production radio sampling now skips protocol queries on unverified factory/old
C6 firmware. It enables them only after identifying a release at or beyond the
documented 2.6.6 workaround. Unknown/older firmware returns an unavailable
diagnostic, rather than executing the unsafe RPC. Native callers use a padded
16-bit scratch buffer and copy only the successful low byte. Host tests inject
a two-byte write, cover unavailable firmware, known old 1.4.7, fixed 2.6.6,
and verify no pre-association protocol RPC.

The actual saved working-night ELF was also disassembled: its radio sampler
does **not** call the new protocol getter. Its failure in the earlier rollback
test means this unsafe query alone does not explain every observation. A
persistent C6 state/calibration issue remains a separate hypothesis.

### Missing RPC responses could crash P4

Two other pinned wrapper getters dereferenced absent responses:
`rpc_wifi_get_config()` copied from `resp` unconditionally, and
`rpc_wifi_ap_get_sta_list()` read `resp->...num` outside its success guard.
Both now preserve the caller's output and return the existing RPC error when
the response is absent/failed. These changes use the same generated-source
patch mechanism and do not modify managed sources.

A host harness compiled from the **unmodified real getter** reproduces a null
read at address `0x68` under ASan/UBSan. The patched real getters pass success,
failure, missing response, null output, interface selection, and response
cleanup tests. The full host suite and P4/XIAO builds pass. These are confirmed
stability defects, not a proven explanation of the latest board failure.

### Additional experiments prepared

1. A temporary P4 image for passive scan, BSSID/channel selection, minimal
   settings, precomputed WPA2 PSK and a no-PSK control was written. No status
   could be collected afterward: application USB did not return. The specific
   crash/startup reason is unknown because no new dump/UART output was obtained.
   Do not count its planned phases as completed tests.
2. A separate small P4 project was built with stock ESP-Hosted 1.4.7, only STA
   and USB CDC, no MeshPN, NAPT, VPN or PSRAM. The stricter association-only
   variant avoids default STA netif handlers, DHCP and config/protocol getters;
   a netif variant is retained separately. Prepared phases include BSSID
   selection, precomputed PSK, modem power-save cycle, clearing fast-connect,
   explicit channel selection and temporary country readback/restoration.
3. A C6 diagnostic app was compiled from pinned 1.4.7 with full RF calibration
   and calibration storage disabled. Its NVS error path preserves NVS rather
   than erasing it. Before radio initialization it uses IDF's
   `esp_ota_mark_app_invalid_rollback()` (without reboot), which verifies that
   another bootable app exists. A 180-second timer then returns to that image.
   This is a **candidate**, not a hardware-verified recovery guarantee: it
   requires the new app to reach its prearm code, and a P4/SDIO restart could
   trigger return before measurements. No C6 image was written. The private
   copy also fixes two 5.5.5 slave-source build incompatibilities and widens
   the native protocol getter buffer.

The diagnostic P4 images add an early RTC boot counter: a second startup goes
to ROM instead of repeatedly running a failing experiment. That guard was
prepared **after** the USB failure and has not been flashed or hardware-tested.
Production sources have no temporary experiment task/guard.

### Current hardware blocker

After the additional P4 flash, the selected board remains physically connected
on USB hub path `2-1.4`, but neither its application nor ROM serial device
enumerates. The exact agreed **20 attempts at 30-second intervals** were
completed. An addressed PORT_RESET and an individual PORT_POWER off/on on
that path also did not restore enumeration; the hub and other ports were not
reset. The latest production image is built and available for restoration,
but it has **not** been written after this failure.

BOOT+RESET was requested only after the 20 attempts. A CH343 UART
`5B91063477` is also present, but its ownership is unconfirmed. Automatic
approval review rejected opening/reconfiguring that UART because it might
belong to another device. Ownership/permission was requested separately; the
rejection was not bypassed and the UART was not opened. Mac Wi-Fi and the
connected Camic S3 were unchanged.

Follow-up artifacts are in the same ignored regression directory:
`followup/` (source/image backups and sanitizer evidence), `isolated/`
(independent P4 test), and `c6-fullcal/` (unflashed C6 candidate). Console files:
`/tmp/meshpn-followup-*.log`, `/tmp/meshpn-isolated-build55.log`,
`/tmp/meshpn-c6-fullcal-build.log`. The existing binding remains
`E8F60AE395D0`. Further on-board experiments require restoring its USB access;
the new Wi-Fi hypotheses have not been marked as resolved or exhausted.

### Further RPC transaction isolation

Continued the investigation while P4 USB was unavailable. A deterministic harness
compiled from the pinned **unmodified** `get_response()` demonstrates that two
synchronous callers can receive each other's responses: after both semaphores
are posted, scheduling caller B first returns the FIFO's response for A. The
per-UID semaphore did not establish ownership of the shared receive queue.

The generated P4 RPC core now retains each synchronous response in its own
transaction slot, checks both UID and response ID, and removes that slot under
the same mutex used to publish responses. Semaphore destruction happens after
removal, preventing an RX task from giving an already deleted semaphore.
Duplicate, orphaned and late replies are freed instead of occupying the next
caller's queue. UID allocation and transaction registration/removal are protected;
allocation failure, table exhaustion and failed TX submission clean up the slot.
This does not serialize entire round trips or hold the mutex while waiting.

The local TX-failure response also lacked its request UID; it now carries that
UID and is published after TX cleanup. The slave-interface macro's failed-send
log read a request already freed by `rpc_send_req()`; it now logs the constant
message ID. These changes are limited to generated copies of pinned 1.4.7
sources. Existing asynchronous RPC handling and active-call shutdown semantics
are not redesigned by this patch.

Tests compile the real patched transaction functions and failed-send macro.
They cover reverse caller scheduling, wrong response ID, duplicate/late replies,
timeout/delivery races, semaphore allocation failure, TX queue rejection, full
transaction table, UID rollover, immediate wakeups, and 4 concurrent callers
with 4000 transactions. ASan/UBSan and a separate ThreadSanitizer run pass;
the complete host suite and P4 build pass. The original FIFO reproduction and
the concurrency harness are retained in `followup/`; console evidence is
`/tmp/meshpn-rpc-core-{host-tests,build,tsan}.log`.

These are additional confirmed communication/stability defects, **not a proven
fix for authentication**. The updated production image has not been flashed:
P4 still does not enumerate. Attempts to reach its saved STA addresses `.8`
and `.10` on the existing home LAN timed out, and the mDNS observation returned
no address. Mac Wi-Fi was unchanged. The standalone association/DHCP and C6
full-calibration candidates remain untested; they are not counted as failures
or successful fixes.
