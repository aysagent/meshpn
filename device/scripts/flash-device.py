#!/usr/bin/env python3
"""Build is done by flash.sh. Select, enter ROM, flash, rediscover, monitor.

Uses pyserial from the ESP-IDF Python environment. Never guesses among boards
or redirects a flash to an unrelated port after USB re-enumeration.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

APP = (0x303A, 0x4001)
ROM = (0x303A, 0x1001)
UART = {(0x10C4, 0xEA60), (0x1A86, 0x7523), (0x1A86, 0x55D4), (0x0403, 0x6001)}


class ApplicationUSBTimeout(RuntimeError):
    """Flash succeeded, but the application's USB identity was not observed."""


def usb_id(port):
    return port.vid, port.pid


def location(port):
    # Linux adds the USB interface suffix, which changes with descriptors.
    return (port.location or "").split(":", 1)[0]


def select_port(ports, explicit, target):
    if explicit:
        matches = [p for p in ports if p.device == explicit]
    else:
        allowed = UART | {ROM} | ({APP} if target == "esp32s3" else set())
        matches = [p for p in ports if usb_id(p) in allowed]
    if len(matches) != 1:
        found = ", ".join(p.device for p in matches) or "none"
        raise RuntimeError(f"Expected one programming port (found: {found}). "
                           "Connect the board or set PORT=/dev/cu.… (Linux: /dev/ttyACM…). "
                           "Use BUILD_ONLY=1 to build without a board.")
    port = matches[0]
    if target == "esp32p4" and usb_id(port) == APP:
        raise RuntimeError("P4 HS NCM is not the programming connector. Select its USB-C/UART port with PORT.")
    return port


def wait_port(original, expected, enumerate_ports, timeout=30, clock=time.monotonic, sleep=time.sleep):
    anchor = location(original)
    if not anchor:
        raise RuntimeError("USB physical location is unavailable; cannot safely follow re-enumeration. "
                           "Enter BOOT manually and select the ROM port explicitly.")
    deadline = clock() + timeout
    while clock() < deadline:
        matches = [p for p in enumerate_ports() if location(p) == anchor and usb_id(p) == expected]
        if len(matches) > 1:
            raise RuntimeError("Ambiguous USB interfaces at the selected board's location; refusing to flash.")
        if matches:
            return matches[0]
        sleep(0.2)
    if expected == APP:
        raise ApplicationUSBTimeout("Flash completed, but application USB CDC did not return. "
                           "Release BOOT and press RESET once; check startup logs if it still fails. "
                           "No other port was selected.")
    raise RuntimeError("Timed out waiting for the selected board to re-enumerate. "
                       "Old firmware needs ONE manual BOOT flash to install auto-flash support. "
                       "A crashed application also needs manual BOOT. No other port was selected.")


def touch(port, serial_factory, sleep=time.sleep):
    # Opening at 115200 prevents a leftover 1200 setting from triggering before
    # we have deliberately asserted DTR. Exclusive access catches another tool.
    with serial_factory(port.device, baudrate=115200, timeout=1, exclusive=True) as connection:
        connection.dtr = True
        connection.baudrate = 1200
        sleep(0.1)
        connection.dtr = False


def application_port(args, original, enumerate_ports, run, wait):
    try:
        return wait(original, APP, enumerate_ports)
    except ApplicationUSBTimeout:
        # BOOT-triggered USB Serial/JTAG download can survive the default RTS
        # core reset: GPIO0 is latched until a full system reset. Do not reset
        # an application, an ambiguous device, or a different physical board.
        anchor = location(original)
        matches = [p for p in enumerate_ports() if anchor and location(p) == anchor
                   and usb_id(p) in {APP, ROM}]
        if len(matches) != 1:
            raise
        port = matches[0]
        if usb_id(port) == APP:  # Reappeared just after the timeout.
            return port
        # Respect IDF's no-reset policy (including secure flashing builds).
        # A missing/unknown manifest must not enable this recovery path.
        try:
            manifest = json.loads((Path(args.build_dir) / "flasher_args.json").read_text())
            options = manifest.get("extra_esptool_args", {})
            reset_allowed = (options.get("chip") == "esp32s3"
                             and options.get("after") == "hard_reset")
        except (OSError, ValueError, AttributeError):
            reset_allowed = False
        if not reset_allowed:
            raise
        print(f"Application USB absent; selected S3 remains in download mode on {port.device}. "
              "Trying ONE full watchdog reset; release BOOT. No flash rewrite.", flush=True)
        # esptool v4 shipped with IDF 5.4 uses underscore option values.
        # Read-only command, followed by a full reset that resamples GPIO0.
        run([sys.executable, "-m", "esptool", "--chip", "esp32s3", "--port", port.device,
             "--before", "no_reset", "--after", "watchdog_reset", "--no-stub", "read_mac"],
            check=True)
        return wait(original, APP, enumerate_ports)


def flash(args, enumerate_ports, serial_factory, run=subprocess.run, wait=wait_port):
    original = select_port(enumerate_ports(), args.port, args.target)
    port = original
    if usb_id(port) == APP:
        if not location(port):
            raise RuntimeError("USB location is unavailable; refusing to reset a board we cannot rediscover.")
        print(f"Entering ROM bootloader through {port.device} (1200-baud touch)…", flush=True)
        touch(port, serial_factory)
        port = wait(original, ROM, enumerate_ports)
    print(f"Flashing {args.target} on {port.device}", flush=True)
    base = ["idf.py", "-C", args.device_dir, "-B", args.build_dir]
    run(base + ["-p", port.device, "flash"], check=True)
    # A successful esptool exit proves flashing, not a healthy application.
    # Native S3 USB changes identity again when the application starts.
    if args.target == "esp32s3" and usb_id(port) == ROM and args.profile == "ncm":
        port = application_port(args, original, enumerate_ports, run, wait)
        print(f"Application USB CDC returned on {port.device}; network/VPN health not tested.", flush=True)
    if args.monitor:
        if usb_id(port) == APP:
            print("Normal MeshPN CDC is quiet; use device:flash:diag for '?' diagnostic snapshots. "
                  "Close monitor before the next flash.", flush=True)
        run(base + ["-p", port.device, "monitor"], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-dir", required=True)
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--target", choices=["esp32s3", "esp32p4"], required=True)
    parser.add_argument("--profile", choices=["ncm", "ecm", "rndis"], required=True)
    parser.add_argument("--port", default=os.environ.get("PORT"))
    parser.add_argument("--monitor", action="store_true")
    args = parser.parse_args()
    try:
        import serial
        from serial.tools.list_ports import comports
        flash(args, comports, serial.Serial)
    except (RuntimeError, OSError, ImportError, subprocess.CalledProcessError) as exc:
        print(f"Flash failed: {exc}\nClose monitor/usb-diag and retry; no automatic port fallback.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
