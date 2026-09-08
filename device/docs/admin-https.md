# Local HTTPS administration

The firmware generates an individual EC P-256 key and self-signed certificate on first boot, stored together in NVS.
The certificate includes meshpn.local, meshpn.home.arpa and the initial 192.168.7.1 address.
It remains the same after ordinary reboots and flashing an app without erasing NVS. Factory reset generates a new identity.

Open https://meshpn.local/ over USB. A self-signed certificate initially produces a browser warning.
Establish trust on a direct, trusted USB connection; compare the browser certificate fingerprint with the device's UART/boot log.
The authenticated status page also shows the fingerprint for later comparison, but a page alone is not independent proof of its own identity.

HTTP on port 80 redirects only; passwords, bearer tokens, logs and APIs are served on HTTPS.
If mDNS is unavailable, enter the USB gateway as an HTTPS IP address.
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
