#!/usr/bin/env python3
"""Verify a bound P4's eFuse MAC and flash using one open ROM connection."""
import argparse
import os
from pathlib import Path
import re
import sys


def write_verified(port, expected_mac, build_dir, chip_factory, flash_main):
    if not re.fullmatch(r"[0-9A-F]{12}", expected_mac):
        raise RuntimeError("Invalid bound P4 MAC; refusing to flash")
    build = Path(build_dir).resolve()
    if not (build / "flash_args").is_file():
        raise RuntimeError("Missing generated flash arguments; refusing to flash")
    chip = chip_factory(port, 115200)
    previous_dir = Path.cwd()
    try:
        chip.connect("no_reset")
        actual_mac = "".join(f"{b:02X}" for b in chip.read_mac())
        if actual_mac != expected_mac:
            raise RuntimeError("ROM MAC does not match the bound board; refusing to flash")
        print(f"Bound P4 ROM MAC verified: {actual_mac}; keeping port open for write", flush=True)
        os.chdir(build)
        flash_main(["--chip", "esp32p4", "--port", port, "-b", "460800",
                    "--before", "no_reset", "--after", "hard_reset",
                    "write_flash", "@flash_args"], esp=chip)
    finally:
        os.chdir(previous_dir)
        chip._port.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--expected-mac", required=True)
    parser.add_argument("--build-dir", required=True)
    args = parser.parse_args()
    import esptool
    from esptool.targets.esp32p4 import ESP32P4ROM
    write_verified(args.port, args.expected_mac, args.build_dir, ESP32P4ROM, esptool.main)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Verified P4 flash failed: {exc}", file=sys.stderr)
        sys.exit(1)
