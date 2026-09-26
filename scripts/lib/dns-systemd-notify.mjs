/** READY for this service only; never installs/starts a unit or notifies during preflight. */
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat } from 'node:fs/promises';
import { boundedInspectRead } from './dns-inspect.mjs';

const fail = () => Object.assign(new Error('DNS_SYSTEMD_NOTIFY_REFUSED'), { code: 'DNS_SYSTEMD_NOTIFY_REFUSED' });
const exec = promisify(execFile);
export async function createDnsSystemdNotifier({ env = process.env, pid = process.pid, ppid = process.ppid,
  read = boundedInspectRead, stat = lstat, run = exec } = {}) {
  try {
    assert.equal(ppid, 1); assert.ok(Number.isInteger(pid) && pid > 1);
    assert.equal(env.NOTIFY_SOCKET, '/run/systemd/notify');
    assert.match(env.INVOCATION_ID ?? '', /^[a-f0-9]{32}$/);
    assert.equal((await read('/proc/1/comm', 64)).trim(), 'systemd');
    assert.ok((await stat('/run/systemd/notify')).isSocket());
    const invocation = env.INVOCATION_ID; let called = false;
    return async (signal) => {
      try {
        assert.equal(called, false); assert.ok(!signal?.aborted); called = true;
        // Keep systemd-notify's default reception barrier; --no-block is forbidden.
        await run('/usr/bin/systemd-notify', ['--ready', `--pid=${pid}`], {
          env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', NOTIFY_SOCKET: '/run/systemd/notify', INVOCATION_ID: invocation },
          timeout: 3000, killSignal: 'SIGKILL', maxBuffer: 2048, signal,
        });
        assert.ok(!signal?.aborted);
      } catch { throw fail(); }
    };
  } catch { throw fail(); }
}
