#!/usr/bin/env python3
"""Build is done by flash.sh. Select, enter ROM, flash, rediscover, monitor.

Uses pyserial from the ESP-IDF Python environment. Never guesses among boards
or redirects a flash to an unrelated port after USB re-enumeration.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

APP = (0x303A, 0x4001)
ROM = (0x303A, 0x1001)
P4_ROM = (0x303A, 0x0012)
P4_PRODUCT = "MeshPN ESP32-P4 HS NCM"
S3_PRODUCT = "Espressif Device"


class ApplicationUSBTimeout(RuntimeError):
    """Flash succeeded, but the application's USB identity was not observed."""


def usb_id(port):
    return port.vid, port.pid


def location(port):
    # Linux adds the USB interface suffix, which changes with descriptors.
    return (port.location or "").split(":", 1)[0]


def is_app(port, target):
    if usb_id(port) != APP:
        return False
    product = getattr(port, "product", None) or ""
    if target == "esp32p4":
        return product == P4_PRODUCT and getattr(port, "manufacturer", None) == "MeshPN"
    return product == S3_PRODUCT and getattr(port, "manufacturer", None) == "Espressif Systems"


def rom_id(target):
    return P4_ROM if target == "esp32p4" else ROM


def select_port(ports, explicit, target):
    if explicit:
        matches = [p for p in ports if p.device == explicit]
    else:
        matches = [p for p in ports if usb_id(p) == rom_id(target)
                   or is_app(p, target)]
    if len(matches) != 1:
        found = ", ".join(p.device for p in matches) or "none"
        raise RuntimeError(f"Expected one programming port (found: {found}). "
                           "Connect the board or set PORT=/dev/cu.… (Linux: /dev/ttyACM…). "
                           "Use BUILD_ONLY=1 to build without a board.")
    port = matches[0]
    if not (is_app(port, target) or usb_id(port) == rom_id(target)):
        raise RuntimeError("Selected USB port does not match this project's board and target chip")
    return port


def serial_number(port):
    serial = (getattr(port, "serial_number", None) or "").upper()
    if not re.fullmatch(r"[0-9A-F]{12}", serial):
        raise RuntimeError(f"{port.device} has no unique 12-hex-digit USB serial")
    return serial


def load_binding(path, target):
    try:
        binding = json.loads(Path(path).read_text())
    except FileNotFoundError as error:
        name = "p4" if target == "esp32p4" else "xiao"
        raise RuntimeError(f"Board is not bound. Run npm run device:bind:{name} once before flashing") from error
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Cannot read board binding {path}: {error}") from error
    if (not isinstance(binding, dict) or binding.get("target") != target or
            not isinstance(binding.get("serial"), str) or
            not re.fullmatch(r"[0-9A-F]{12}", binding["serial"])):
        raise RuntimeError(f"Invalid board binding for {target}: {path}")
    return binding


def check_app_binding(port, binding):
    if (not is_app(port, binding["target"]) or
            (binding["target"] == "esp32p4" and serial_number(port) != binding["serial"])):
        raise RuntimeError(f"{port.device} is not the bound {binding['target']} board")


def rom_mac(port, target, run):
    command = [sys.executable, "-m", "esptool", "--chip", target,
               "--port", port.device, "--before", "no_reset", "--after",
               "no_reset", "--no-stub", "read_mac"]
    result = run(command, check=True, capture_output=True, text=True)
    output = result.stdout or ""
    match = re.search(r"\bMAC:\s*((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b", output)
    if not match:
        raise RuntimeError(f"Cannot verify ROM MAC on {port.device}; refusing to flash")
    return match.group(1).replace(":", "").upper()


def bind(args, enumerate_ports, serial_factory, run=subprocess.run, wait=None):
    if wait is None:
        wait = wait_port
    candidates = [p for p in enumerate_ports() if is_app(p, args.target)]
    port = select_port(candidates, args.port, args.target)
    if not is_app(port, args.target) or not location(port):
        raise RuntimeError("Bind requires the running MeshPN application with a USB location")
    if args.target == "esp32p4":
        serial = serial_number(port)
    else:
        # S3 firmware uses the generic TinyUSB serial "123456". Read its
        # actual eFuse MAC in ROM once, then return it to the application.
        touch(port, serial_factory)
        rom = wait(port, ROM, enumerate_ports)
        if usb_id(rom) != ROM or location(rom) != location(port):
            raise RuntimeError("ROM port identity/location changed during binding")
        serial = rom_mac(rom, args.target, run)
        run([sys.executable, "-m", "esptool", "--chip", "esp32s3",
             "--port", rom.device, "--before", "no_reset", "--after",
             "watchdog_reset", "--no-stub", "read_mac"], check=True)
        returned = wait(port, APP, enumerate_ports)
        if not is_app(returned, args.target):
            raise RuntimeError("MeshPN S3 application did not return after binding")
    path = Path(args.binding_file)
    if path.exists():
        old = load_binding(path, args.target)
        if old["serial"] != serial:
            raise RuntimeError(f"{path} already binds a different board; remove it explicitly to rebind")
        print(f"Board already bound: {serial}", flush=True)
        return
    path.write_text(json.dumps({"target": args.target, "serial": serial}, indent=2) + "\n")
    print(f"Bound {args.target} serial {serial} in {path}", flush=True)


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
                           "Press RESET once without BOOT if it still stays in ROM; check startup logs. "
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
    binding = load_binding(args.binding_file, args.target)
    if is_app(original, args.target):
        check_app_binding(original, binding)
    port = original
    if is_app(port, args.target):
        if not location(port):
            raise RuntimeError("USB location is unavailable; refusing to reset a board we cannot rediscover.")
        print(f"Entering ROM bootloader through {port.device} (1200-baud touch)…", flush=True)
        touch(port, serial_factory)
        port = wait(original, rom_id(args.target), enumerate_ports)
    if usb_id(port) != rom_id(args.target) or location(port) != location(original):
        raise RuntimeError("ROM port identity/location changed; refusing to flash")
    if args.target == "esp32p4" and is_app(original, args.target):
        # The checked app serial is derived from this P4's eFuse MAC, and the
        # ROM appeared at the same physical USB location. Closing the P4 ROM
        # port after a separate read_mac can make macOS drop the CDC device
        # before the subsequent flash open. Keep ROM MAC verification when
        # starting from ROM, where no application identity was available.
        print(f"Bound P4 application {binding['serial']} became ROM at the same USB location", flush=True)
    elif args.target != "esp32p4" and rom_mac(port, args.target, run) != binding["serial"]:
        raise RuntimeError("ROM MAC does not match the bound board; refusing to flash")
    print(f"Flashing {args.target} on {port.device}", flush=True)
    base = ["idf.py", "-C", args.device_dir, "-B", args.build_dir]
    if args.target == "esp32p4":
        # The P4 USB-OTG ROM port can disappear while idf.py runs its second
        # Ninja/CMake pass. flash.sh has already built and checked the image,
        # so start esptool directly while the verified ROM port is still live.
        flash_args = Path(args.build_dir) / "flash_args"
        if not flash_args.is_file():
            raise RuntimeError(f"Missing generated flash arguments: {flash_args}")
        if is_app(original, args.target):
            run([sys.executable, "-m", "esptool", "--chip", "esp32p4",
                 "--port", port.device, "-b", "460800", "--before", "no_reset",
                 "--after", "hard_reset", "write_flash", "@flash_args"],
                cwd=args.build_dir, check=True)
        else:
            # Starting in ROM still requires an eFuse MAC check. Keep its
            # serial connection open through the write: closing after a
            # separate read_mac can leave macOS with a stale USB device.
            run([sys.executable, str(Path(__file__).with_name("flash-p4-verified.py")),
                 "--port", port.device, "--expected-mac", binding["serial"],
                 "--build-dir", str(Path(args.build_dir).resolve())], check=True)
    else:
        run(base + ["-p", port.device, "flash"], check=True)
    # A successful esptool exit proves flashing, not a healthy application.
    # Native USB changes identity again when the application starts.
    if usb_id(port) == rom_id(args.target) and args.profile == "ncm":
        if args.target == "esp32s3":
            port = application_port(args, original, enumerate_ports, run, wait)
            check_app_binding(port, binding)
        else:
            port = wait(original, APP, enumerate_ports)
            check_app_binding(port, binding)
        print(f"Application USB CDC returned on {port.device}; network/VPN health not tested.", flush=True)
    if args.monitor:
        if is_app(port, args.target):
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
    parser.add_argument("--binding-file")
    parser.add_argument("--bind", action="store_true")
    parser.add_argument("--monitor", action="store_true")
    args = parser.parse_args()
    if not args.binding_file:
        args.binding_file = str(Path(__file__).parents[1] / f".board-binding-{args.target}.json")
    try:
        import serial
        from serial.tools.list_ports import comports
        if args.bind:
            bind(args, comports, serial.Serial)
        else:
            flash(args, comports, serial.Serial)
    except (RuntimeError, OSError, ImportError, subprocess.CalledProcessError) as exc:
        print(f"Flash failed: {exc}\nClose monitor/usb-diag and retry; no automatic port fallback.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
