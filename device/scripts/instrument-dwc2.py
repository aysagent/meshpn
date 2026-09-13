#!/usr/bin/env python3
"""Generate read-only ESP32-S3 slave-mode DWC2 hooks in a pinned build copy."""
import argparse
import hashlib
from pathlib import Path

SOURCE_SHA256 = "66a3d4c49bf78bfca5d7d49a4ff28d0b839a8695912a2c9c29344beae475e25a"


def instrument(source: bytes) -> str:
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("TinyUSB DWC2 source changed: re-audit instrumentation; refusing to build")
    text = source.decode()

    def replace(old, new):
        nonlocal text
        if text.count(old) != 1:
            raise ValueError(f"Expected one DWC2 anchor: {old!r}")
        text = text.replace(old, new, 1)

    anchor = "static uint16_t epin_write_tx_fifo(dwc2_regs_t *dwc2, uint8_t epnum);"
    replace(anchor, '#include "meshvpn_dwc2_diag.h"\n' + anchor)
    for anchor in ["static void handle_bus_reset(uint8_t rhport) {", "void dcd_edpt_close_all(uint8_t rhport) {"]:
        replace(anchor, anchor + "\n  meshvpn_dwc2_reset();")
    anchor = "    // Schedule packets to be sent within interrupt\n    edpt_schedule_packets(rhport, epnum, dir);"
    replace(anchor, '''    if (dir == TUSB_DIR_IN && epnum > 0) {
      dwc2_regs_t *mesh_regs = DWC2_REG(rhport);
      meshvpn_dwc2_submit(ep_addr, total_bytes, mesh_regs->dieptxf[epnum - 1],
                          mesh_regs->grxfsiz, mesh_regs->gahbcfg);
    }
''' + anchor)
    anchor = "  return total_bytes_written;\n}"
    replace(anchor, "  meshvpn_dwc2_refill(epnum | TUSB_DIR_IN_MASK, total_bytes_written);\n" + anchor)
    anchor = "static void handle_epin_slave(uint8_t rhport, uint8_t epnum, dwc2_diepint_t diepint_bm) {"
    start = text.index(anchor)
    end = text.index("\n}", start) + 2
    original = text[start:end]
    hooked = original.replace("      dcd_event_xfer_complete(", "      meshvpn_dwc2_complete(epnum | TUSB_DIR_IN_MASK, xfer->total_len);\n      dcd_event_xfer_complete(")
    hooked = hooked.replace("    epin_write_tx_fifo(dwc2, epnum);", "    meshvpn_dwc2_txfe(epnum | TUSB_DIR_IN_MASK);\n    epin_write_tx_fifo(dwc2, epnum);")
    replace(original, hooked)
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("output must not overwrite original driver")
    result = instrument(args.source.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.output.exists() or args.output.read_text() != result:
        args.output.write_text(result)


if __name__ == "__main__":
    main()
