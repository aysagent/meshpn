# Local HTTPS administration

HTTPS is **disabled by default** for testing. Open `http://meshpn.local/` or `http://192.168.7.1/` in this mode.
In **Admin connection**, check **Enable HTTPS**, choose **Save connection setting**, then **Reboot to apply**.
Open the displayed HTTPS address after reboot and log in again. The checkbox can also disable HTTPS using the same save/reboot sequence.
The choice is stored in NVS and overrides `CONFIG_MESHVPN_WEB_HTTPS`, which now only specifies the initial/factory-reset default.
Once this firmware is installed, switching modes does not require reflashing.
HTTP-only mode keeps login and USB/AP ingress isolation from upstream STA, but passwords/tokens are not encrypted in transit.
HTTP boot does not initialize the TLS identity; certificate download/import requests over HTTP are rejected.
Enabling HTTPS prepares/validates the identity before saving the mode, so preparation failure leaves the previous setting active.
Any existing NVS identity is preserved when HTTPS is disabled.

The firmware generates an individual EC P-256 key and self-signed certificate when HTTPS is first enabled (or on first boot with HTTPS as the default), stored together in NVS.
New certificates include meshpn.local, meshpn.home.arpa and the initial USB/AP addresses 192.168.7.1 and 192.168.4.1. Existing and imported identities are not replaced: use meshpn.local on AP with an older certificate, or import a new identity if direct AP-IP access without a name warning is required.
It remains the same after ordinary reboots and flashing an app without erasing NVS. Factory reset generates a new identity.

Open https://meshpn.local/ over USB or the device's own AP. A self-signed certificate initially produces a browser warning.
Establish trust on a direct, trusted USB connection; compare the browser certificate fingerprint with the device's UART/boot log.
The authenticated status page also shows the fingerprint for later comparison, but a page alone is not independent proof of its own identity.

HTTP on port 80 redirects only; passwords, bearer tokens, logs and APIs are served on HTTPS.
If mDNS is unavailable, try https://meshpn.home.arpa/ using the gateway DNS, or the USB/AP gateway as an HTTPS IP address.
When subnet conflict recovery changes that IP, the certificate still covers the canonical name; an IP literal may produce a name warning.

## Personal CA (no browser warning after setup)

Use OpenSSL 3.x on your computer. On macOS, ensure the OpenSSL 3 binary is on PATH rather than the bundled older LibreSSL.

```bash
bash device/scripts/create-admin-ca.sh device/tls
```

The script refuses to overwrite an existing directory. It generates:

- ca.crt / ca.key: your personal CA certificate and private signing key.
- device.crt / device.key: a one-year server certificate and matching private key for the dongle.

Install **ca.crt** on the hosts that will administer the dongle. Keep **ca.key** private on the computer.
On iPhone, after installing the certificate profile, enable its TLS trust in
Settings → General → About → Certificate Trust Settings, as described by [Apple](https://support.apple.com/en-us/102390).
On macOS, use Keychain Access to install the CA and explicitly trust it for SSL.

In the dongle's HTTPS admin page, open **HTTPS certificate → Import** and select **device.crt** and **device.key**.
The key pair and meshpn.local name are validated before saving. Reboot to apply.
Never upload ca.key to the dongle. A failed import leaves the active identity in use.
For renewal, issue another server certificate under the same CA and import its matching key; host CA trust remains valid.

The development build does not encrypt NVS/PSRAM at rest. HTTPS protects transport; physical flash/core-dump access is a separate concern.
Mandatory replacement of the default admin password is optional:
`CONFIG_MESHVPN_WEB_REQUIRE_PASSWORD_CHANGE=n` by default for testing.

If HTTPS fails at boot, the device does not silently serve credentials over HTTP. Existing BOOT recovery remains available:
hold BOOT for five seconds to erase **all NVS settings**, including WiFi profiles, admin password, HTTPS preference and identity.
It returns to the build default (HTTP in the supplied configuration). This is a factory reset, not a settings-preserving rollback.
