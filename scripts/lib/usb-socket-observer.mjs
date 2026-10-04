/** Read-only metadata for synthetic :443 flows in the isolated diagnostics VM. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
export function startSocketObserver(event) {
  assert.match(fs.readFileSync('/proc/cmdline', 'utf8'), /(?:^|\s)meshpn.usb-diagnostics=1(?:\s|$)/);
  assert.equal(fs.readFileSync('/sys/class/dmi/id/sys_vendor', 'utf8').trim(), 'QEMU');
  let busy, stopped = false, sequence = 0;
  const sample = () => {
    if (busy || stopped) return;
    busy = (async () => {
      const observedMonotonicMs = performance.now();
      const args = ['-tinmoHa', '( dport = :443 or sport = :443 )'];
      try {
        const [host, exit] = await Promise.all([
          exec('/usr/bin/ss', args, { timeout: 5000, maxBuffer: 65536 }),
          exec('/usr/bin/ip', ['netns', 'exec', 'exit', '/usr/bin/ss', ...args], { timeout: 5000, maxBuffer: 65536 }),
        ]);
        event({ event: 'socket-sample', phase: 0, sequence: sequence++, observedMonotonicMs,
          host: host.stdout.trim(), exit: exit.stdout.trim() });
      } catch (error) {
        event({ event: 'socket-observer-error', phase: 0, observedMonotonicMs, error: error.code || error.message });
      }
    })().finally(() => { busy = null; });
  };
  const timer = setInterval(sample, 2000); sample();
  return async () => { stopped = true; clearInterval(timer); await busy; };
}
