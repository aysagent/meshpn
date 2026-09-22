# MeshPN USB WiFi dongle

ESP-IDF firmware for XIAO ESP32-S3 and Waveshare ESP32-P4-WIFI6. USB Ethernet
and WiFi SoftAP → IPv4 NAT → WiFi STA.
VPN, WireGuard and policy enforcement are **not implemented**. USB compatibility expansion is deferred.

## Build and flash

```bash
./device/scripts/setup-macos.sh       # once; ESP-IDF 5.4.1
source ~/.zshrc
./device/scripts/flash.sh             # existing NCM profile
```

For the Waveshare ESP32-P4-WIFI6:

```bash
BOARD=waveshare_esp32_p4_wifi6 PORT=/dev/cu.wchusbserialXXXX \
  ./device/scripts/flash.sh ncm monitor
```

Flash the P4 through the board's USB-C/USB-UART connector. MeshPN NCM uses the
separate four-pin USB 2.0 HS connector. See the
[board-specific wiring and ESP32-C6 compatibility notes](docs/waveshare-esp32-p4-wifi6.md).

For XIAO/NCM, `npm run device:flash` builds first, sends a **1200-baud CDC touch**
to the running firmware, waits for its ROM programming port, flashes, then waits
for the application USB port to return. No Wi-Fi, admin password or network access
is involved. Close monitor/usb-diag before flashing. This is physical-USB access,
with the same trust boundary as an attached programmer; it is not a network API.

**Install this support once using BOOT with the old firmware** (release BOOT
after connecting, before running the command). A hung application,
disabled ROM USB download eFuses, or a profile without CDC still requires manual
download mode. On P4 the USB-UART connector uses esptool's normal DTR/RTS reset;
the separate HS connector is not used for flashing. Automatic port selection
refuses ambiguous devices and follows the selected physical USB location after
reset. A successful flash/USB reappearance does not certify Wi-Fi or VPN health.

After manual BOOT entry on S3, the default RTS reset can leave GPIO0 latched in
download mode even after releasing the button. If application USB does not return
within 30 seconds and the same physical board still exposes its ROM USB port,
the helper attempts **one full watchdog reset**, without rewriting flash. It
respects the build's `no_reset` policy and never switches to another board. If
recovery fails, release BOOT and press RESET once, then inspect startup logs.
This recovery does not apply to P4 or USB-UART programming ports.
See Espressif's [USB Serial/JTAG download-mode reset explanation](https://docs.espressif.com/projects/esptool/en/latest/esp32s3/troubleshooting.html#leaving-download-mode-in-usb-serial-jtag-mode).

With no board attached, use `BUILD_ONLY=1 npm run device:flash` explicitly;
ordinary flash now exits with an error instead of silently building only.
Set `PORT` explicitly if several serial devices are connected. Each board/profile/defaults combination gets a separate
`device/build-…` directory and sdkconfig; previous builds and settings are preserved. Keep the target-specific
`dependencies.lock.esp32s3` and `dependencies.lock.esp32p4` files in version control.
The dependency manager applies the iot_bridge lwIP patches to your ESP-IDF checkout.

## WireGuard compiler performance comparison

Normal `npm run device:flash` now compiles only the WireGuard dependency with
`-O2`, including ChaCha20/Poly1305. Other components keep their IDF optimization
settings. This does not change algorithms, authentication, MTU, queues, copying,
Wi-Fi settings or core affinity. It is not a measured speed guarantee.

For a control build using the previous compiler settings:

```bash
WIREGUARD_PERF=0 npm run device:flash
# Optimized build (default):
npm run device:flash
```

The two variants use separate `build-…-wg0` / `build-…-wg1` directories. The
configure log prints the selected mode. Direct IDF users can pass
`-D MESHVPN_WIREGUARD_PERF=OFF` or `ON` explicitly; otherwise the CMake option
defaults to ON in a fresh build directory. Existing CMake selections persist.
Compare the same client, VPN endpoint and speed-test server with the phone's
own VPN disabled. Record CPU0/CPU1 load during transfer, not only after it.

### WireGuard performance diagnostics

Run a speed test with WireGuard enabled, then open the VPN section. It retains
the **last active CPU sample** (normally 2 seconds, at least 64 KiB of combined
encrypt/decrypt data) and shows its age, CPU0/CPU1 load and crypto mean time per
call. Idle windows and empty keepalives do not replace it. This is a recent
window, not a whole-test average or peak. It survives disconnect/reconnect and
transport changes until another active window or reboot; always check its age.

Copy `cpu.wireguard_active` and `vpn.wireguard.crypto` from Status → Diagnostics
after the test (or save the full status JSON). Crypto counters are cumulative
since boot, independent of API readers. They measure **transport data** calls,
including keepalives, not handshake/X25519 work. Bytes include plaintext padding
and failed decrypt attempts, exclude authentication tags, and are not delivered
IP/application bytes. `failed` counts decrypt authentication failures; encryption
has no failure return. `core_calls` records the core at call entry.

Times are wall-clock microseconds around the original library calls, including
interrupts/preemption, not pure CPU cycles or time to transmit over Wi-Fi. Calls
are attributed at completion; a call crossing a sample boundary can contribute
time from the previous interval. CPU and crypto snapshots are adjacent, not
atomic; both interval lengths are exposed. Timing adds two clock reads and a
short counter lock per call. No payload/key logging, allocation or change to
crypto algorithms is introduced. Missing CPU sampling is unknown, not zero load.

Switching to TCP preserves WireGuard keys, Address, DNS and keepalive in NVS.
The server/Endpoint field is currently **shared**: after using another TCP
server, restore the WireGuard Endpoint when switching back. A blank private key
or PSK input keeps the saved key; only the explicit PSK-removal checkbox clears it.

### Socket stream recovery and diagnostics

The socket worker tracks the five-second incomplete-frame deadline per framed
IP packet, not per sequence of TCP reads. Completing a packet and beginning the
next in the same read starts a new deadline; trickling bytes of one unfinished
packet does not extend its deadline. The wire format is unchanged.

TX drains up to 32 already-queued frames per batch, with no fill delay. The
queue is bounded at 256 frames; the worker can additionally own at most 32
in-flight frames. The queue, batch and RX buffer are allocated in PSRAM. One read is capped at 4096 bytes and one
write at the remaining batch, so neither direction has an unbounded drain loop.
Partial writes preserve framing/order; `packets_out` counts only complete frames
accepted by the TCP socket, not delivery to the exit. Queue expiry still happens
before dequeue; in-flight frames use a five-second per-frame send deadline.
Batching does not guarantee a loss-free tunnel when the exit/uplink is slower
than producers, and TCP-over-TCP still has head-of-line blocking.

The socket protocol carries complete raw IPv4 packets, not lwIP checksum-offload
metadata. IPv4 and TCP/UDP/ICMP checksums are therefore recalculated after
NAPT/MSS rewriting before packets cross the stream boundary. The same repair is
performed before received packets are injected into lwIP and once more at the
final USB/AP Ethernet-driver boundary, after reverse NAPT and TTL changes. This
is local packet normalization and does not change the clean-vpn framing protocol.
`vpn.socket.packet_path.lan_egress` reports IPv4 frames observed at that final
boundary, how many checksum fields actually needed repair, and malformed frames.

`vpn.socket.last_failure` retains `reason`, `error`, `age_sec` and configuration
`generation` after successful reconnects. It records connection attempts as well
as active stream failures. Reasons include `connect`, `remote_closed`, `select`,
`recv`, `send`, `invalid_frame`, `rx_frame_timeout` and `tx_frame_timeout`.
`rx_timeouts`/`tx_timeouts` and the last failure are since boot, not reset by a
transport change. A requested reconfiguration is not recorded as a failure.
The VPN page shows this history separately from the current `last_error`.

After flashing, repeat opening sites on the same phone/USB connection for at
least 30 seconds. If it still fails, save Diagnostics with `vpn` and `dns`;
compare before/after counters, especially `queue_full`, `queue_expired`,
`reconnects`, `socket.last_failure`, and `socket.packet_path`. The packet-path
object shows whether packets reached the exit with the tunnel source address
and whether replies were reverse-NAPT routed back to USB/AP. Diagnostics can be
frozen with **Pause updates** before selecting/copying JSON. No exit-side
protocol update is needed.

## Control a board attached to a Mac from a Linux server

The Mac opens an outbound reverse SSH tunnel to the server. Enable macOS
**System Settings → General → Sharing → Remote Login** for the Mac user and set
up SSH-key authentication in both directions. The server needs no direct route
to the Mac and no router port-forward or public reverse-proxy port is needed.
From the repo on the Mac, run:

```bash
npm run device:remote tunneluser@SERVER
```

Leave that terminal running while using the board. If Mac Wi-Fi drops during
an AP test, this command reconnects the tunnel after the original network
returns. On the Linux server, from
the repo, connect with the same macOS username as the Linux username, or pass
the Mac username explicitly:

```bash
npm run device:remote:connect
npm run device:remote:connect macuser
npm run device:remote:connect macuser 'cd ~/dev/home/meshpn && PORT=/dev/cu.usbmodemXXXX npm run device:flash'
```

For commands in the Mac checkout, save its absolute path and macOS SSH user
once on Linux (the path defaults to `~/dev/home/meshpn` on the Mac until set).
The command writes only `device/.remote-mac.json` on Linux, ignored by git.
A fast-forward-only update is then:

```bash
npm run device:remote:config -- /Users/YOUR_MAC_USER/path/to/meshpn YOUR_MAC_USER
npm run device:remote:repo -- git status --short
npm run device:remote:repo -- git pull --ff-only
```

`git pull --ff-only` is explicit, never part of a benchmark, and will refuse
conflicting local changes. `MESHPN_MAC_REPO_DIR` and `MESHPN_MAC_SSH_USER`
override the saved values for one command. The Mac checkout needs Node.js,
npm, iperf3 and the same prerequisites as ordinary `device:perf` runs.

To test the board AP while this reverse tunnel is the only way into the Mac,
first connect the Mac to the board AP manually once and save its Wi-Fi password
in macOS, then reconnect to the normal Wi-Fi. Keep USB NCM connected: the job
discovers the board and its AP SSID via USB before changing Wi-Fi. From Linux:

```bash
npm run device:remote:ap-test -- user@SERVER --ap-tcp-paced
```

The command launches a detached job on the Mac, waits through any tunnel
outage, restores the previous Wi-Fi and DHCP route, copies the complete job
directory to `device/perf-remote-results/<job-id>/` on Linux, and prints only
local file paths for `report.md`, `result.json`, and the logs. It does not put
raw logs in the agent's command output. `--ap-tcp-paced` (8/10/12/14 Mbit/s)
is the default; `--ap-tcp-up` or other compatible perf-runner options may be
passed instead. The result also contains `state.json`, `worker.log`, and all
raw runner files. No AP password is passed in command arguments or stored in
the result. The Mac may ask for permission to change Wi-Fi; grant it before a
headless run. If association or restore fails, the job records the error and a
separate watchdog retries restoration when the worker exits; if the tunnel
cannot come back, use the Mac locally and collect the job later.

For separate launch/collection (or a retry after a server command times out):

```bash
npm run device:remote:repo -- npm run --silent device:perf:ap-managed -- user@SERVER --ap-tcp-paced
npm run device:remote:collect -- JOB_ID
```

The first command prints only the job ID. Both the one-step and separate
collector accept `MESHPN_MAC_SSH_USER` and `MESHPN_REMOTE_PORT`; collector wait
defaults to six hours (`MESHPN_REMOTE_COLLECT_WAIT_MINUTES` can override it).
If Mac Remote Login is unavailable, the job cannot start. If association with
the AP fails, the worker attempts to restore the original Wi-Fi and records
the error. The Wi-Fi switch is not a test of reconnect/sleep behavior of the
board itself.

The tunnel listens on **127.0.0.1:22022 on the server**, forwarding to the
Mac's local SSH service. Both commands accept `MESHPN_REMOTE_PORT` if another
server-local port is needed. Server SSH must permit remote TCP forwarding and
must not force wildcard binding (`GatewayPorts yes`); verify with
`ss -ltn '( sport = :22022 )'` that only loopback is listening. The first
server-to-Mac SSH login should verify and save the Mac's host key; the command
uses the stable host-key alias `meshpn-mac-via-tunnel`. Do not forward an SSH
agent or expose this port publicly. For an interactive remote monitor command,
set `MESHPN_REMOTE_TTY=1` on the Linux command. When the Mac is off or asleep,
the tunnel drops and hardware actions must wait. Firmware still needs a serial
download port (and, on XIAO, bootloader mode); the tunnel does not switch the
board into that mode. The normal XIAO NCM firmware has no continuous USB CDC
console; use `/api/logs`, diagnostic firmware, or a UART adapter as appropriate.

## First login

Open **http://meshpn.local/** over USB, or **http://192.168.7.1/**.
SoftAP provides internet access, not administration; USB administration works without a WiFi uplink.
HTTPS is disabled by default for testing (`CONFIG_MESHVPN_WEB_HTTPS=n`). Login and WiFi credentials travel unencrypted over USB in this mode;
authentication and WiFi-side ingress isolation remain enabled.

To enable HTTPS, check **Admin connection → Enable HTTPS**, click **Save connection setting**, then **Reboot to apply**.
Open the displayed **https://meshpn.local/** address and log in again; HTTP now only redirects and does not accept login/API requests.
Uncheck and save/reboot to return to HTTP. No reflashing is required after installing this firmware.
The preference persists in NVS; `CONFIG_MESHVPN_WEB_HTTPS` only sets the initial/factory-reset default, not a compile-time restriction.
Before enabling from HTTP, the device prepares/validates its unique certificate; if that fails the saved mode is unchanged.
HTTP boot does not initialize the identity; certificate download/import is forbidden over HTTP. Disabling HTTPS preserves the identity for later use.
See [HTTPS setup](docs/admin-https.md) for fingerprint verification, a personal CA and certificate import.

Default password: **admin**. For development, changing it is optional.
To require a change before modifying settings, enable
`CONFIG_MESHVPN_WEB_REQUIRE_PASSWORD_CHANGE` in menuconfig (meshvpn Web).
The initial password is configurable with `CONFIG_MESHVPN_WEB_ADMIN_PASSWORD_DEFAULT`.
A password change revokes the current session. Sessions expire after 30 minutes idle or 8 hours total.

## WiFi and status

- Saved networks are listed on opening the page, with priority, enabled state, edit/connect/delete controls. Passwords are never returned.
- Nearby networks are scanned automatically when the admin page opens. **Scan networks** repeats the search.
  A requested scan waits while association/DHCP is in progress.
- Up to 16 saved profiles; manual/hidden SSID, open/WPA2/WPA3 Personal, priority -1000…1000.
  Higher priority wins, then RSSI; a working connection stays active.
- Failed connections fall through to other available profiles, with bounded rounds and 2–60 second backoff.
  The last selected profile (or the sole enabled profile) is also retried directly when an iPhone hotspot stops
  advertising in scans; the WiFi driver performs three bounded association retries before profile failover.
  **Disconnect / pause** disables automatic reconnect until resumed.
- Existing single-network credentials migrate to the versioned profile list.
- Only 2.4 GHz is supported. Enterprise authentication and upstream captive-portal login are outside this implementation.
- Status polls every 2 seconds while visible: chip temperature, internal RAM and PSRAM free/minimum/largest block,
  USB/AP counters, AP SSID/channel/client count/NAT, DNS cache statistics, build/IDF version and certificate fingerprint.
- If the router subnet overlaps USB or AP, the device chooses another private /24, also avoiding the other LAN. Renew DHCP/reconnect the affected client;
  use `meshpn.local` to find the new address. An imported certificate may not cover the new IP literal.

DHCP advertises each LAN's own gateway as DNS. The proxy accepts USB requests and AP-gateway requests, forwards UDP/TCP to the uplink resolver,
validates responses, has three bounded workers and a small TTL cache.
`meshpn.home.arpa` is an ordinary-DNS alternative to mDNS.
Apple/Google/Windows connectivity names are no longer redirected to the dongle.

Administration and mDNS are available from USB and the board's own AP. The ingress hook blocks management and DNS from upstream STA,
including requests routed to a LAN gateway; AP clients may use DNS at their own gateway. IPv6 is disabled.
Confirm this on hardware using the [acceptance checklist](docs/current-improvements.md).

## LED indicators

The yellow user/status LED blinks while STA is disconnected. When VPN is enabled,
it also keeps blinking until the VPN connection is established, and resumes
blinking if that connection drops (including when DIRECT fallback is allowed).
With VPN disabled, STA connectivity alone makes it steady. State is refreshed
once per second from the applied configuration. Steady light means a connection,
not a successful Internet/DNS/HTTPS probe. The user-LED off setting still overrides
all indications.

In the admin UI, **LED indicators → Enable user/status LED** controls the XIAO
ESP32-S3 user LED (GPIO21, active low). Uncheck it and click **Save LED setting**
to disable both blinking and steady illumination immediately. Re-enabling restores
normal Wi-Fi status indication. The setting survives reboot; factory reset restores
the enabled default. It applies in this firmware, not in an external bootloader.

The second checkbox describes the **charge LED** and is deliberately disabled,
with an indeterminate state: the MCU cannot read or control that light. On this board
it is wired to the charger, not a GPIO; see the [Seeed documentation and schematics](https://wiki.seeedstudio.com/xiao_esp32s3_getting_started/#resources).
No charging/power settings are changed to suppress it. The Waveshare P4 board's
only on-board LED is likewise a non-controllable 5 V power indicator. Board
profiles without a GPIO LED have no editable user-LED control.

Authenticated `POST /api/admin/leds` accepts only `{"user_enabled":false}` (or true).
It commits NVS before changing the active setting; a save failure leaves active
indication unchanged. `GET /api/status` exposes `leds.user.controllable/enabled`
and `leds.charge.present/controllable/enabled`; charge `enabled=null` means unknown,
not off. The normal USB/AP management authorization and password policy apply.

## STA + AP + USB throughput experiment

SoftAP is enabled by default alongside STA and USB NCM:

- SSID: **MeshPN_XXXXXX**, with the final six MAC hex digits; exact name is shown in USB admin status.
- WPA2 password: **meshpn-test** (development default; change before non-test use).
- Up to four clients. AP gateway/DHCP/DNS: **192.168.4.1/24**, unless a subnet conflict requires reassignment.
- AP stays enabled without uplink; internet resumes when STA connects. Pause disconnects STA, not AP or USB.
- AP clients have internet and admin/mDNS access. USB and AP are routed LANs, not a fully isolated guest network.

Build settings are under ESP-IoT-Bridge / SoftAP Config: `CONFIG_BRIDGE_SOFTAP_SSID`,
`CONFIG_BRIDGE_SOFTAP_PASSWORD`, `CONFIG_BRIDGE_SOFTAP_SSID_END_WITH_THE_MAC`, `CONFIG_BRIDGE_SOFTAP_MAX_CONNECT_NUMBER`.
Set `CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP=n` for a USB-only comparison build. AP settings are build-time for this experiment.
Configure uplink via USB first, then connect the test client to the AP. You can power the configured dongle from a USB charger for an AP-only test.

AP and STA share the radio and channel, with STA taking channel priority; both WiFi hops use airtime.
The firmware permits HT40 on both interfaces, but the upstream AP controls the shared APSTA channel.
HT40 is used only when it is negotiated with the upstream AP; a status uplink `secondary_channel` of
`0` means the current connection is HT20 even if the configured interface bandwidth reports 40 MHz.
No speedup is claimed before measurements. See [AP/USB comparison procedure](docs/apsta-benchmark.md).

### Automatic benchmarks (Mac)

Для диагностики кратких переполнений USB-очереди после обновления прошивки:
`npm run device:perf:usb-bursts -- 62.84.120.30 --start-delay 60`.
Только 6/7/8 Мбит/с; подробнее [методика и ограничения](perf-testing.md#короткие-переполнения-usb-tx-queue).

Connect USB and join the board AP on the Mac, then close the admin browser tab:

```bash
npm run device:perf -- user@SERVER:22 --paths both --quick
```

Remove `--quick` for the full TCP/UDP, simultaneous AP+USB, latency and endurance suite (~75 minutes plus overhead).
The target port is **SSH**, not iperf3. The runner starts its own iperf3 servers, verifies per-interface routes,
collects board telemetry and writes `device/perf-results/<run>/report.md` plus raw data.
Missing dependencies produce installation instructions, never automatic installation.
See [runner options, prerequisites and limitations](perf-testing.md). Tests: `npm run device:perf:test`.

## Memory / IP lists

The UI's **IP-list memory benchmark** measures synthetic binary-search lookups in PSRAM and frees the allocation afterwards.
It does not install routes or measure VPN/NAT speed; at least 2 MiB PSRAM is reserved during the test.

```bash
node device/scripts/compile-ip-ranges.mjs country.cidrs country.bin
```

Input: one IPv4 address/CIDR per line, optional `#` comments. The compiler merges overlapping/adjacent ranges.
Output: a 16-byte `MPNIPV4\0` header (version/count in little endian), then 8 bytes per inclusive range.
This is a membership set, not an ordered list of routing actions. The firmware does not yet load or enforce these files.

## Recovery and tests

Hold BOOT for five seconds during operation to erase NVS settings, WiFi profiles and the HTTPS identity, then reboot.
With HTTPS enabled, the new certificate will need verification. BOOT recovery starts before the web server, so it also works if that server cannot start.

Logs are available in the UI and authenticated `GET /api/logs`; USB CDC console output remains disabled.
The 12 KiB log ring is allocated once in PSRAM on XIAO, freeing its previous internal-RAM
storage. Allocation failure leaves default log output active and does not prevent boot;
there is no internal-RAM fallback on PSRAM boards. The hook captures normal task-context
ESP_LOG output, not cache-disabled EARLY/DRAM logging or panic output. Its try-lock/drop
behavior, ring capacity and API remain unchanged; no allocation is done per log entry.
UART: GPIO43/44 (D6/D7). Hardware notes: [xiao-esp32s3.md](docs/xiao-esp32s3.md).

If HTTP is unresponsive and no UART adapter is available, use the **opt-in USB diagnostic build**:

```bash
npm run device:flash:diag
# After flashing: release BOOT and boot normally. Close serial monitors/admin tabs.
npm run device:diag
```

The second command (Python 3, standard library only) autodetects a single CDC port, requests
buffered logs, probes HTTP `/login`, then requests another snapshot. Pass `-- --port /dev/cu.usbmodem...`
if multiple ports exist; `-- --host 192.168.4.1` changes the HTTP probe destination, not the USB log transport.
`-- --no-http` only reads one snapshot. A missing reply can mean a normal/non-diagnostic firmware,
wrong/busy port, USB fault or failure before diagnostics startup; it is not proof of an HTTP fault.

Snapshots include firmware build, uptime/reset reason, internal heap, HTTP startup/request stage,
HTTP accepted-connection count (plain HTTP only) and recent logs. They do not rely on the HTTP server.
The existing CDC descriptor is unchanged; ESP_LOG is **not** redirected to USB and there is no continuous stream.
Only `?` requests are supported: no reboot, erase, shell or configuration commands. Requests are coalesced/rate-limited;
CDC callbacks never wait or print, and the worker's transmit has a deadline.

This build lets a **physically attached USB host read logs without admin authentication**; logs may contain
network names/addresses. It adds a 4 KiB task stack and a transient 16 KiB PSRAM snapshot, so do not use it for
baseline performance testing. Return to `npm run device:flash` for the normal build; separate build directories
keep diagnostic settings out of the normal profile. NVS settings are not erased by either command.
Host utility tests: `npm run device:diag:test`. Actual CDC/NCM coexistence still requires hardware validation.

If diagnostics report `start/server-error` / `ESP_ERR_HTTPD_TASK`, the HTTP task could not
be created. In the reported `ecffbaf` boot the largest internal heap block was 11264 bytes,
smaller than the 12288-byte admin stack. ESP-IDF 5.4.1 can leave the listening socket open
on this failure, so TCP connects while HTTP receives no response. Resetting NVS is not a remedy.
CPU snapshot buffers now explicitly use PSRAM (no internal fallback on PSRAM boards), and
the optional sampler starts after the server. HTTP/TLS stacks remain internal and unchanged.
After flashing, check `/login` from USB and AP, then login, WiFi scan/save and `/api/status`
CPU updates. In diagnostics, expect `web.stage=ready` (or a later request stage) and no
server-start error. Repeat on a normal build before performance measurements; HTTPS still
needs a separate on-device check if enabled.

```bash
bash device/scripts/test-host.sh
```

See [current implementation and checks](docs/current-improvements.md) for test coverage and remaining hardware verification.
