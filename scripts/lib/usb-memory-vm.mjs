/** Injected ONLY into the disposable soak image, never imported by production. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import v8 from 'node:v8';
import vm from 'node:vm';
assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.usb-soak=1(?:\s|$)/);
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
const destination = `/run/e2e-memory-${process.pid}.json`;
const request = `/run/e2e-memory-gc-${process.pid}`;
// Explicit final lab-only collection separates live V8 data from retained RSS.
v8.setFlagsFromString('--expose_gc');
const collect = vm.runInNewContext('gc');
function sample() {
  const forcedGc = fs.existsSync(request);
  if (forcedGc) { fs.unlinkSync(request); collect(); }
  fs.writeFileSync(destination, JSON.stringify({ pid: process.pid, monotonicMs: performance.now(), forcedGc,
    ...process.memoryUsage(), handles: process.getActiveResourcesInfo().sort() }));
}
sample(); setInterval(sample, 1000).unref();
