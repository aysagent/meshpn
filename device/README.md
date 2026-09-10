# MeshPN USB WiFi dongle

ESP-IDF firmware for XIAO ESP32-S3. USB Ethernet and WiFi SoftAP → IPv4 NAT → WiFi STA.
VPN, WireGuard and policy enforcement are **not implemented**. USB compatibility expansion is deferred.

## Build and flash

```bash
./device/scripts/setup-macos.sh       # once; ESP-IDF 5.4.1
source ~/.zshrc
./device/scripts/flash.sh             # existing NCM profile
```

Hold BOOT while connecting USB to enter download mode. Without a serial port the script builds only.
Set `PORT` explicitly if several serial devices are connected. Each board/profile/defaults combination gets a separate
`device/build-…` directory and sdkconfig; previous builds and settings are preserved. Keep `dependencies.lock` in version control.
The dependency manager applies the iot_bridge lwIP patches to your ESP-IDF checkout.

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
No speedup is claimed before measurements. See [AP/USB comparison procedure](docs/apsta-benchmark.md).

### Automatic benchmarks (Mac)

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
