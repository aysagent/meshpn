import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("instrument_dwc2", ROOT / "scripts/instrument-dwc2.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = ROOT / "managed_components/espressif__tinyusb/src/portable/synopsys/dwc2/dcd_dwc2.c"


class Tests(unittest.TestCase):
    def test_changed_source_rejected(self):
        with self.assertRaisesRegex(ValueError, "re-audit"):
            module.instrument(b"unknown")

    @unittest.skipUnless(SOURCE.exists(), "managed dependencies not installed")
    def test_hooks_preserve_usb_operations(self):
        raw = SOURCE.read_bytes()
        old = raw.decode()
        new = module.instrument(raw)
        self.assertEqual(new, module.instrument(raw))
        self.assertEqual(SOURCE.read_bytes(), raw)
        for call in ["dcd_event_xfer_complete(", "epin_write_tx_fifo(", "edpt_schedule_packets("]:
            self.assertEqual(new.count(call), old.count(call))
        for call in ["meshvpn_dwc2_submit(", "meshvpn_dwc2_refill(", "meshvpn_dwc2_complete(", "meshvpn_dwc2_txfe("]:
            self.assertEqual(new.count(call), 1)
        self.assertEqual(new.count("meshvpn_dwc2_reset();"), 2)
        self.assertIn("mesh_regs->dieptxf[epnum - 1]", new)
        self.assertLess(new.index("meshvpn_dwc2_submit("), new.index("    // Schedule packets to be sent within interrupt"))
        self.assertIn("meshvpn_dwc2_complete(epnum | TUSB_DIR_IN_MASK, xfer->total_len);\n      dcd_event_xfer_complete", new)
        self.assertIn("meshvpn_dwc2_refill(epnum | TUSB_DIR_IN_MASK, total_bytes_written);\n  return total_bytes_written", new)

    @unittest.skipUnless(SOURCE.exists(), "managed dependencies not installed")
    def test_actual_slave_handler_and_fifo_writer(self):
        source = module.instrument(SOURCE.read_bytes())

        def function(anchor):
            start = source.index(anchor)
            return source[start:source.index("\n}", start)+2]

        # Minimal RAM model, not a bus emulator. Exercise the generated bodies,
        # especially completion-before-event ordering and zero-byte refills.
        harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "meshvpn_dwc2_diag.h"
typedef struct { uint32_t tsiz,dtxfsts; } dwc2_dep_t;
typedef struct { dwc2_dep_t ep[1][7]; dwc2_dep_t epin[7]; uint32_t fifo[7][32],diepempmsk; } dwc2_regs_t;
typedef union { uint32_t value; struct { uint32_t xfer_size:19,packet_count:10,pad:3; }; } dwc2_ep_tsize_t;
typedef struct { bool xfer_complete,txfifo_empty; } dwc2_diepint_t;
typedef struct { uint16_t max_size,total_len; uint8_t *buffer; void *ff; } xfer_ctl_t;
static dwc2_regs_t regs;
static xfer_ctl_t transfers[7];
static struct { uint16_t ep0_pending[2]; } _dcd_data;
static int64_t now;
static unsigned events,order,writes;
int64_t esp_timer_get_time(void) { return now; }
#define DWC2_REG(port) ((void)(port), &regs)
#define TUSB_DIR_IN 1
#define TUSB_DIR_IN_MASK 0x80
#define XFER_CTL_BASE(ep,dir) (&transfers[ep])
#define DTXFSTS_INEPTFSAV_Msk 0xffff
#define XFER_RESULT_SUCCESS 0
#define tu_min16(a,b) ((a)<(b)?(a):(b))
#define tu_bit_test(a,b) ((a)&(1u<<(b)))
static void edpt_schedule_packets(uint8_t rhport,uint8_t ep,uint8_t dir) { (void)rhport;(void)ep;(void)dir; assert(false); }
static void dcd_event_xfer_complete(uint8_t rhport,uint8_t ep,uint32_t bytes,int result,bool isr) {
  (void)rhport; assert(ep==0x84 && result==0 && isr);
  meshvpn_dwc2_stats_t s; meshvpn_dwc2_get_stats(&s);
  assert(s.isr_completions==++order); /* Hook runs before event publication. */
  now+=100; meshvpn_dwc2_task(ep,bytes); events++;
}
static void tu_hwfifo_write(volatile uint32_t *fifo,void *buffer,uint16_t bytes,void *unused) {
  (void)fifo;(void)buffer;(void)unused; assert(bytes==64); writes++;
  regs.ep[0][4].dtxfsts-=bytes/4;
  dwc2_ep_tsize_t t={.value=regs.ep[0][4].tsiz}; t.xfer_size-=bytes; t.packet_count--; regs.ep[0][4].tsiz=t.value;
}
static void tu_hwfifo_write_from_fifo(volatile uint32_t *fifo,void *buffer,uint16_t bytes,void *unused) {
  tu_hwfifo_write(fifo,buffer,bytes,unused);
}
'''
        harness += function("static uint16_t epin_write_tx_fifo(dwc2_regs_t *dwc2, uint8_t epnum) {")
        harness += function("static void handle_epin_slave(uint8_t rhport, uint8_t epnum, dwc2_diepint_t diepint_bm) {")
        harness += r'''
int main(void) {
  uint8_t buffer[128]; transfers[4]=(xfer_ctl_t){.max_size=64,.total_len=128,.buffer=buffer};
  meshvpn_dwc2_bind(0x84); meshvpn_dwc2_submit(0x84,128,32u<<16,62,1);
  dwc2_ep_tsize_t t={.xfer_size=128,.packet_count=2}; regs.ep[0][4].tsiz=t.value; regs.ep[0][4].dtxfsts=32;
  regs.diepempmsk=1u<<4;
  handle_epin_slave(0,4,(dwc2_diepint_t){.txfifo_empty=true});
  assert(writes==2 && regs.diepempmsk==0 && transfers[4].buffer==buffer+128);
  now=6000; handle_epin_slave(0,4,(dwc2_diepint_t){.xfer_complete=true});
  assert(events==1);
  meshvpn_dwc2_stats_t s; meshvpn_dwc2_get_stats(&s);
  assert(s.service_us==6000 && s.task_us==100 && s.refill_bytes==128 && s.txfe_irqs==1);
  assert(epin_write_tx_fifo(&regs,4)==0);
  meshvpn_dwc2_get_stats(&s); assert(s.refill_empty==1);
  meshvpn_dwc2_submit(0x84,0,32u<<16,62,1); transfers[4].total_len=0;
  handle_epin_slave(0,4,(dwc2_diepint_t){.xfer_complete=true});
  meshvpn_dwc2_get_stats(&s); assert(events==2 && s.zlp_completions==1 && s.task_timed==1);
}
'''
        with tempfile.TemporaryDirectory(prefix="meshpn-dwc2-hooks-") as work:
            binary = str(Path(work)/"test")
            subprocess.run([os.environ.get("CC", "cc"), "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-pthread", "-I"+str(ROOT/"tests/usb_stubs"),
                            "-I"+str(ROOT/"tests/cpu_stubs"), "-I"+str(ROOT/"components/meshvpn_usb/include"),
                            "-", str(ROOT/"components/meshvpn_usb/meshvpn_dwc2_diag.c"), "-o", binary],
                           input=harness, text=True, check=True)
            subprocess.run([binary], check=True)


if __name__ == "__main__":
    unittest.main()
