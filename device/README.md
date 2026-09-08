# MeshPN USB WiFi dongle

ESP-IDF firmware for XIAO ESP32-S3. USB Ethernet → IPv4 NAT → WiFi.
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

Open **https://meshpn.local/** over USB, or **https://192.168.7.1/**.
There is no setup SoftAP; USB administration works without a WiFi uplink.
HTTP only redirects to HTTPS and does not accept login/API requests.

The first boot generates a unique self-signed certificate. Verify the SHA-256 fingerprint using a trusted USB connection/UART log before trusting it.
See [HTTPS setup](docs/admin-https.md) for installing a personal CA and importing its server certificate.

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
  USB counters, DNS cache statistics, build/IDF version and certificate fingerprint.
- If the router subnet overlaps USB, the device chooses another private /24. Renew the host DHCP lease or reconnect USB;
  use `meshpn.local` to find the new address. An imported certificate may not cover the new IP literal.

DNS advertises the USB gateway via DHCP. It proxies UDP/TCP to the uplink resolver, validates responses, has three bounded workers and a small TTL cache.
`meshpn.home.arpa` is an ordinary-DNS alternative to mDNS.
Apple/Google/Windows connectivity names are no longer redirected to the dongle.

Administration, DNS and mDNS are restricted to USB. The ingress hook blocks local management ports from WiFi,
including requests routed to the USB IP; IPv6 is disabled. Confirm this on hardware using the [acceptance checklist](docs/current-improvements.md).

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
The new certificate will need verification. BOOT recovery starts before the HTTPS server, so it also works if HTTPS cannot start.

Logs are available in the UI and authenticated `GET /api/logs`; USB CDC console output remains disabled.
UART: GPIO43/44 (D6/D7). Hardware notes: [xiao-esp32s3.md](docs/xiao-esp32s3.md).

```bash
bash device/scripts/test-host.sh
```

See [current implementation and checks](docs/current-improvements.md) for test coverage and remaining hardware verification.
