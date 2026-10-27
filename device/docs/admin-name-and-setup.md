# Device name and automatic Wi-Fi setup

The default admin address is **http://dongle.local/** on USB Ethernet, the
device's AP and STA network. Existing installations without a saved device
name use this default after upgrading. AP SSID and IP addresses are unchanged.

In **Admin → Device name**, enter `travel-dongle` and press **Save and apply
name**. A pasted `travel-dongle.local` also works. Names are lowercase ASCII,
1–63 letters/digits/hyphens, beginning and ending with a letter or digit.
The mDNS name changes without reboot and is persisted in NVS. Local DNS answers
both the configured `.local` and `.home.arpa` names using the ingress gateway.
Gateway IP access remains available. Factory reset removes the custom name.

Authenticated `POST /api/admin/hostname` accepts `{"name":"travel-dongle"}`.
Status exposes `device_name`, `hostname`, `admin_next_url` and `captive_portal`.

## Setup portal

While STA has no IPv4 uplink, including no saved profiles or saved networks
being unavailable, USB/AP gateway DNS answers A queries with its ingress
gateway. These setup answers have TTL zero and are never cached by the proxy.
Other record types receive no fabricated address. HTTP connectivity checks,
including `/hotspot-detect.html`, `/generate_204` and `/connecttest.txt`, receive
a no-cache redirect to the gateway's login page. Sign in, use Scan to find Wi-Fi,
then Save and connect. When STA obtains IPv4, wildcard DNS and HTTP setup
redirects stop. Explicit local-name DNS continues to work. VPN failure with a
connected Wi-Fi uplink does not activate the portal or bypass the kill switch.

This is traditional DNS/HTTP portal detection. It does not advertise a plaintext
DHCP option 114 API as RFC 8908 CAPPORT, which requires authenticated HTTPS:
[RFC 8908 §4](https://www.rfc-editor.org/rfc/rfc8908.html#section-4).
External TLS connections are not intercepted. With HTTPS enabled, probes point
at the existing HTTPS admin, where certificate trust still applies. Automatic
browser presentation depends on the phone OS, interface and remembered network
state; firmware cannot force it. Manual fallback: `http://192.168.10.1/login`
on USB or `http://192.168.11.1/login` on AP (HTTPS when enabled).

## HTTPS names

New generated certificates cover the configured `.local` and `.home.arpa` names
and initial USB/AP gateway IPs. Renaming preserves an existing/imported
certificate. The admin shows if it does not cover the new name. Import a pair
for that name and reboot to activate it. Old identities remain loadable after
an upgrade; browsers still enforce name/trust checks.

To create an identity for a custom name:

```
bash device/scripts/create-admin-ca.sh device/tls-travel travel-dongle
```

The CA private key stays on the host. Import validates the configured name and
matching key and never silently replaces an existing trusted identity.
