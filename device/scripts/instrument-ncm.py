#!/usr/bin/env python3
"""Generate an instrumented build copy; never edit managed_components.

Pinned to espressif/tinyusb 0.21.0~1. Reject changed inputs until the hooks have
been audited again. The replacement calls the original xfer exactly once and
only observes its result; all other insertions are read-only diagnostics.
"""
import argparse
import hashlib
from pathlib import Path

SOURCE_SHA256 = "7a73d088e40a32064d4142a78dfb72745e01c04b7abdfb6fed4392bdcdc3e30b"

HELPER = '''
#include "meshvpn_ncm_diag.h"
static void mesh_ncm_observe(meshvpn_ncm_event_t event, uint32_t bytes, uint16_t frames) {
  meshvpn_ncm_state_t state = {
    .pool = XMIT_NTB_N,
    .glue = ncm_interface.xmit_glue_ntb != NULL,
    .active = ncm_interface.xmit_tinyusb_ntb != NULL,
    .glue_frames = ncm_interface.xmit_glue_ntb ? ncm_interface.xmit_glue_ntb_datagram_ndx : 0,
    .max_ntb = ncm_interface.xmit_max_ntb_size,
    .max_datagrams = ncm_interface.xmit_max_datagrams,
  };
  for (unsigned i = 0; i < XMIT_NTB_N; i++) {
    state.free += ncm_interface.xmit_free_ntb[i] != NULL;
  }
  #if XMIT_NTB_N > 1
  state.ready = ncm_interface.xmit_ready_count;
  #else
  state.ready = ncm_interface.xmit_ready_ntb[0] != NULL;
  #endif
  meshvpn_ncm_record(event, &state, bytes, frames);
}
'''


def instrument(source: bytes) -> str:
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("TinyUSB NCM source changed: re-audit instrumentation for the new dependency; refusing to build")
    text = source.decode("utf-8")

    def replace(old, new):
        nonlocal text
        if text.count(old) != 1:
            raise ValueError(f"Expected exactly one NCM hook anchor: {old[:100]!r}")
        text = text.replace(old, new, 1)

    anchor = "CFG_TUD_MEM_SECTION static ncm_epbuf_t ncm_epbuf;"
    replace(anchor, anchor + "\n" + HELPER)
    anchor = "  usbd_edpt_xfer(0, ncm_interface.ep_in, ncm_interface.xmit_tinyusb_ntb->data, ncm_interface.xmit_tinyusb_ntb->nth.wBlockLength, false);"
    replace(anchor, '''  uint16_t mesh_frames = 0;
  for (unsigned i = 0; i < CFG_TUD_NCM_IN_MAX_DATAGRAMS_PER_NTB; i++) {
    if (!ncm_interface.xmit_tinyusb_ntb->ndp_datagram[i].wDatagramLength) break;
    mesh_frames++;
  }
  bool mesh_submitted = usbd_edpt_xfer(0, ncm_interface.ep_in, ncm_interface.xmit_tinyusb_ntb->data, ncm_interface.xmit_tinyusb_ntb->nth.wBlockLength, false);
  mesh_ncm_observe(mesh_submitted ? MESH_NCM_START : MESH_NCM_START_ERROR,
                   ncm_interface.xmit_tinyusb_ntb->nth.wBlockLength, mesh_frames);''')
    anchor = "    // -> everything is fine\n    return true;"
    replace(anchor, "    // -> everything is fine\n    mesh_ncm_observe(MESH_NCM_SAMPLE, 0, 0);\n    return true;")
    replace("  return false;\n} // tud_network_can_xmit",
            "  mesh_ncm_observe(MESH_NCM_BUSY, 0, 0);\n  return false;\n} // tud_network_can_xmit")
    replace("} // tud_network_xmit", "  mesh_ncm_observe(MESH_NCM_SAMPLE, 0, 0);\n} // tud_network_xmit")
    replace("} // netd_init", "  mesh_ncm_observe(MESH_NCM_INIT, 0, 0);\n} // netd_init")
    anchor = "  } else if (ep_addr == ncm_interface.ep_in) {\n    // transmission of an NTB finished"
    replace(anchor, '''  } else if (ep_addr == ncm_interface.ep_in) {
    if (ncm_interface.xmit_tinyusb_ntb) {
      mesh_ncm_observe(result == XFER_RESULT_SUCCESS ? MESH_NCM_COMPLETE : MESH_NCM_COMPLETE_ERROR, xferred_bytes, 0);
    } else {
      mesh_ncm_observe(result == XFER_RESULT_SUCCESS ? MESH_NCM_ZLP : MESH_NCM_ZLP_ERROR, xferred_bytes, 0);
    }
    // transmission of an NTB finished''')
    anchor = "    if (!xmit_insert_required_zlp(rhport, xferred_bytes)) {\n      xmit_start_if_possible(rhport);\n    }"
    replace(anchor, anchor + "\n    mesh_ncm_observe(MESH_NCM_SAMPLE, 0, 0);")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error("output must not overwrite the original driver")
    generated = instrument(args.source.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.output.exists() or args.output.read_text() != generated:
        args.output.write_text(generated)


if __name__ == "__main__":
    main()
