#!/usr/bin/env python3
"""Exercise the installed DWC2 FIFO allocator against RAM-backed registers.

Not a bus/IRQ test. Compile the actual allocator body, not a second copy of
its arithmetic; unrelated controller code cannot run on a host.
"""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
driver = root / 'device/managed_components/espressif__tinyusb/src/portable/synopsys/dwc2/dcd_dwc2.c'
source = driver.read_text()

def function(start):
    assert source.count(start) == 1
    offset = source.index(start)
    return source[offset:source.index('\n}', offset) + 2]

harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
typedef struct { uint32_t grxfsiz, dieptxf0, dieptxf[6]; } dwc2_regs_t;
typedef struct { uint8_t ep_count, ep_in_count; } dwc2_controller_t;
static dwc2_regs_t regs;
static const dwc2_controller_t _dwc2_controller[]={{7,5}};
static struct { uint16_t dfifo_top; uint8_t allocated_epin_count; } _dcd_data;
static struct { uint16_t bm_double_buffered; } _tud_cfg;
#define DWC2_REG(port) (&regs)
#define TUSB_DIR_OUT 0
#define tu_edpt_number(ep) ((ep)&15)
#define tu_edpt_dir(ep) ((ep)>>7)
#define tu_div_ceil(a,b) (((a)+(b)-1)/(b))
#define TU_ASSERT(cond) do { if(!(cond)) return false; } while(0)
#define DIEPTXF0_TX0FD_Pos 16
#define DIEPTXF_INEPTXFD_Pos 16
#define TU_ATTR_ALWAYS_INLINE
'''
harness += function('TU_ATTR_ALWAYS_INLINE static inline uint16_t calc_device_grxfsiz(')
harness += '\n' + function('static bool dfifo_alloc(')
harness += r'''
int main(void) {
  for(unsigned cdc=0;cdc<=1;cdc++) for(unsigned dbl=0;dbl<=1;dbl++) {
    memset(&regs,0,sizeof(regs)); memset(&_dcd_data,0,sizeof(_dcd_data));
    unsigned net=cdc?4:2;
    _tud_cfg.bm_double_buffered=dbl?(1u<<net):0;
    _dcd_data.dfifo_top=256; /* ESP32-S3: 1024-byte FIFO RAM, slave mode. */
    regs.grxfsiz=calc_device_grxfsiz(64,7);
    assert(regs.grxfsiz==62);
    assert(dfifo_alloc(0,0x80,64,false));
    if(cdc) {
      assert(dfifo_alloc(0,0x81,8,false));
      assert(dfifo_alloc(0,0x82,64,true));
      assert(dfifo_alloc(0,0x02,64,true));
      assert((regs.dieptxf[1]>>16)==16); /* CDC stays single-buffered. */
    }
    assert(dfifo_alloc(0,0x80|(net-1),64,false));
    assert(dfifo_alloc(0,0x80|net,64,true));
    assert(dfifo_alloc(0,net,64,true));
    assert((regs.dieptxf[net-1]>>16)==(dbl?32:16));
    assert((regs.dieptxf0>>16)==16 && regs.grxfsiz==62);
    assert(_dcd_data.dfifo_top-regs.grxfsiz==(cdc?128:146)-16*dbl);
    assert(_dcd_data.allocated_epin_count==(cdc?5:3));
  }
  puts("Actual DWC2 allocator: NCM 64/128B, CDC unchanged, FIFO capacity: OK");
}
'''
with tempfile.TemporaryDirectory(prefix='meshpn-fifo-') as work:
    binary = str(Path(work) / 'test')
    subprocess.run([os.environ.get('CC', 'cc'), '-x', 'c', '-std=c11', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined', '-', '-o', binary],
                   input=harness, text=True, check=True)
    subprocess.run([binary], check=True)
