# XIAO ESP32-S3 hardware notes

Target: ESP32-S3R8, 240 MHz, 8 MiB PSRAM, 8 MiB flash, 2.4 GHz WiFi.
The single USB-C port provides USB OTG Full-Speed (12 Mbps raw).
It shares the PHY with USB-Serial-JTAG.

| Function | Pin |
|---|---|
| LED, active low | GPIO21 |
| UART TX / RX | GPIO43 / GPIO44 (D6 / D7) |
| BOOT | GPIO0 |

NCM remains the existing profile for iPhone/macOS. CDC-ACM is included for descriptor compatibility,
but ESP_LOG is not routed to it. Debug via UART or the HTTPS log page.
USB compatibility expansion and new composite profiles are deferred.

USB LAN initially uses 192.168.7.0/24, gateway 192.168.7.1.
WiFi STA receives its address/DNS from the router. SoftAP is disabled.
A subnet conflict causes selection of a different private /24; renew DHCP/reconnect USB and open https://meshpn.local/.

USB must stay usable without WiFi because it is the provisioning interface.
A connected uplink lights the LED; otherwise it blinks.

To flash: hold BOOT while connecting USB, release, run `./device/scripts/flash.sh`.
To reset configuration while running: hold BOOT for five seconds. This also removes the HTTPS certificate/key.
See [README](../README.md) for first login, password settings, and HTTPS trust.

The current sync USB TX retry and NCM buffer tuning are preserved.
Historical throughput experiments are in [benchmark-gonogo.md](benchmark-gonogo.md).
New firmware needs hardware regression checks for enumeration, sleep/resume, power stability and throughput.
