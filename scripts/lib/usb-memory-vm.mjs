/** Injected ONLY into the disposable soak image, never imported by production. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import v8 from 'node:v8';
import vm from 'node:vm';
import { createRequire } from 'node:module';
assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.usb-soak=1(?:\s|$)/);
assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
const destination = `/run/e2e-memory-${process.pid}.json`;
const request = `/run/e2e-memory-gc-${process.pid}`;
const diagnostics = /(?:^|\s)meshpn.usb-diagnostics=1(?:\s|$)/.test(fs.readFileSync('/proc/cmdline', 'utf8'));
const native = diagnostics ? createRequire(import.meta.url)('../../native/tun_linux/build/Release/tun_linux.node') : null;
const trimRequest = `/run/e2e-memory-trim-${process.pid}`;
// Explicit final lab-only collection separates live V8 data from retained RSS.
v8.setFlagsFromString('--expose_gc');
const collect = vm.runInNewContext('gc');
function sample() {
  const forcedGc = fs.existsSync(request);
  if (forcedGc) { fs.unlinkSync(request); collect(); }
  const trim = diagnostics && fs.existsSync(trimRequest);
  if (trim) fs.unlinkSync(trimRequest);
  const nativeMemory = native?.labMemoryStats(trim);
  fs.writeFileSync(destination + '.tmp', JSON.stringify({ pid: process.pid, monotonicMs: performance.now(), forcedGc,
    ...process.memoryUsage(), ...(native ? { nativeMemory } : {}), handles: process.getActiveResourcesInfo().sort() }));
  fs.renameSync(destination + '.tmp', destination);
}
sample(); setInterval(sample, 1000).unref();
