# STA + SoftAP + USB benchmark

This revision enables a WPA2 AP while preserving the USB NCM interface and saved STA profile manager.
AP and USB clients have separate DHCP subnets and simultaneous IPv4 NAPT to the same STA uplink.
No VPN or policy routing is active yet. Throughput has not been measured on hardware.

## Connect

1. Flash with `./device/scripts/flash.sh`. Its defaults hash creates a new build/sdkconfig with AP enabled.
   Existing custom build directories may still have AP disabled: inspect `CONFIG_BRIDGE_DATA_FORWARDING_NETIF_SOFTAP`.
2. Over USB, open `http://meshpn.local/` (HTTPS if enabled), configure/connect the upstream WiFi.
3. Join **MeshPN_XXXXXX**, password **meshpn-test**. The suffix is the AP MAC's last three bytes in hexadecimal.
   These are development credentials, configurable in ESP-IoT-Bridge / SoftAP Config.
4. Confirm DHCP: normally `192.168.4.x`, gateway and DNS `192.168.4.1`. USB remains `192.168.7.x`/gateway `192.168.7.1`.
   Overlapping uplink subnets trigger reassignment; AP clients are disconnected to encourage fresh DHCP. Rejoin/renew if needed.
5. USB admin status shows `net.ap_active`, `ap_ssid`, `ap_channel`, `ap_clients`, `ap_napt`, `ap_dhcps_dns`, `ap_ip4_rx`.
   Both `ap_napt` and `usb_napt` should be true once the interfaces are up. Passwords are not returned in status/logs.

The admin is available on USB and the dongle's own SoftAP gateway; it remains blocked from the upstream STA/home WiFi. mDNS remains USB-only for now. From AP, the gateway DNS service and HTTP(S) admin are allowed alongside DHCP and routed internet.
This does not provide full guest/client isolation: routed access to the home LAN or USB hosts is not blocked by a general guest firewall.
Keep the known test password confined to testing or change it in the build configuration.

## Measure the intended path

Use a separate AP test client and a USB-connected computer for admin/telemetry, or power the dongle from a charger after provisioning.
If a phone is connected both to USB Ethernet and the AP, its route preference may silently choose USB and invalidate the comparison.
Disable cellular fallback and other active network paths on the test client. Existing phone VPNs/proxies can also skew results.

Place an iperf3 server on the router's LAN, preferably wired, to separate dongle throughput from ISP speed.
For example (replace the address with your LAN server):

```bash
# On the LAN server:
iperf3 -s
# On the AP test client, one TCP flow for 30 seconds in each direction:
iperf3 -c 192.168.1.100 -t 30
iperf3 -c 192.168.1.100 -t 30 -R
```

Repeat at least three times, then repeat via USB on the same client if possible. Use the same STA network, channel, position and server.
Avoid opening/reloading the admin page during the timed interval: page opening triggers an off-channel WiFi scan.
Record whether the existing two-second status polling is active. Separately test AP and USB traffic at the same time.

| Path | Down / up Mbps | Ping under load | STA RSSI / channel | Clients | Internal/DMA/PSRAM minimum free |
|---|---|---|---|---|---|
| USB, AP enabled but idle | | | | | |
| AP, USB idle / management only | | | | | |
| AP + USB simultaneous | | | | | |
| Optional USB-only build (AP disabled) | | | | | |

[Espressif documents](https://docs.espressif.com/projects/esp-idf/en/v5.4.1/esp32s3/api-guides/wifi.html#home-channel)
that AP/STA coexistence uses the same home channel, with the station taking priority.
Both interfaces are configured for HT40 but actual channel width is negotiated; this is not a guarantee of higher throughput.
AP forwarding bypasses USB Full-Speed, but shares radio airtime between receive and retransmit. Reconnect/channel changes and scans can disrupt clients.

## Acceptance and regression

- AP never advertises an open network: the radio is stopped during initial AP creation and configured with WPA2 before restart.
- STA/AP/USB all work after boot; AP stays present without uplink, and internet resumes after router reboot or profile switching.
- AP TCP/UDP DNS works; from STA, DNS on either LAN gateway is blocked.
- HTTP/HTTPS/mDNS and HTTPD control ports are inaccessible from AP and STA, including traffic addressed to the USB gateway.
- Test router subnets `192.168.4.0/24`, `192.168.7.0/24`, and a wider `192.168.0.0/16`: neither LAN may overlap uplink or the other LAN.
- Test four AP clients, USB unplug/replug, phone sleep/resume, and 30–60 minutes of traffic with no resets or shrinking minimum heap.
- Keep the historical [USB benchmark](benchmark-gonogo.md) separate: its 8.13/6.5 Mbps numbers are not measurements of this revision.
