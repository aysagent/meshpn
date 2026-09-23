/** Bounds and namespace-only resource accounting for the real-browser soak. */
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, readlinkSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { assertIdle } from './transparent-soak.mjs';

export function browserSoakOptions(args) {
  const options = { browser: 'all', seconds: 300, concurrency: 4 }, seen = new Set();
  for (const arg of args) {
    if (arg === '--help') { options.help = true; continue; }
    const match = /^--(browser|seconds|concurrency|report)=(.+)$/.exec(arg);
    if (!match || seen.has(match[1])) throw new Error('invalid or duplicate browser soak argument');
    seen.add(match[1]);
    if (['seconds', 'concurrency'].includes(match[1])) {
      if (!/^[1-9]\d*$/.test(match[2])) throw new Error('positive integer required');
      options[match[1]] = Number(match[2]);
    } else options[match[1]] = match[2];
  }
  if (!['all', 'chrome', 'firefox'].includes(options.browser)) throw new Error('browser must be all, chrome or firefox');
  if (options.seconds < 1 || options.seconds > 3600) throw new Error('seconds must be 1..3600 per browser');
  if (options.concurrency < 2 || options.concurrency > 12) throw new Error('concurrency must be 2..12');
  return options;
}

export const namespaceArgs = ['--user', '--map-current-user', '--net', '--mount', '--pid', '--fork',
  '--mount-proc', '--keep-caps', '--kill-child=SIGKILL'];

export function assertBrowserNamespace(env = process.env) {
  assert.ok(env.MESHPN_PARENT_NETNS && env.MESHPN_PARENT_PIDNS, 'use public browser soak launcher');
  assert.notEqual(readlinkSync('/proc/self/ns/net'), env.MESHPN_PARENT_NETNS, 'private network namespace required');
  assert.notEqual(readlinkSync('/proc/self/ns/pid'), env.MESHPN_PARENT_PIDNS, 'private PID namespace required');
  assert.equal(process.pid, 1, 'worker must own namespace init lifetime');
  assert.equal(readlinkSync('/proc/self'), '1', 'proc must describe the private PID namespace');
}

export function namespaceResources() {
  assert.equal(process.pid, 1, 'never scan host processes');
  const tree = { live: 0, zombies: 0, fds: 0, rss: 0 };
  for (const pid of readdirSync('/proc').filter((name) => /^\d+$/.test(name))) {
    try {
      const status = readFileSync(`/proc/${pid}/status`, 'utf8');
      if (/^State:\s+Z/m.test(status)) { tree.zombies++; continue; }
      const rss = /^VmRSS:\s+(\d+) kB$/m.exec(status);
      const fds = readdirSync(`/proc/${pid}/fd`).length;
      tree.live++; tree.fds += fds; tree.rss += Number(rss?.[1] ?? 0) * 1024;
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ESRCH') throw error;
    }
  }
  const active = {};
  for (const kind of process.getActiveResourcesInfo()) active[kind] = (active[kind] ?? 0) + 1;
  return { tree, worker: { memory: process.memoryUsage(), fds: readdirSync('/proc/self/fd').length, active } };
}

export function assertBrowserResources(current, baseline) {
  assert.ok(current.tree.live >= 2 && current.tree.live <= 64, 'browser tree process budget');
  assert.ok(current.tree.zombies <= 64, 'zombie budget');
  assert.ok(current.tree.fds <= 4096, 'browser tree FD budget');
  // Summed RSS counts shared browser pages in every process. A cold Chrome tree
  // on this fixture already measured ~1.6 GiB; this is not unique physical RAM.
  assert.ok(current.tree.rss <= 3072 * 1048576, 'summed browser tree RSS budget');
  assert.ok(current.worker.memory.rss <= 512 * 1048576, 'worker RSS budget');
  if (baseline) {
    assert.ok(current.worker.fds <= baseline.worker.fds, 'idle worker FDs grew');
    assert.ok(current.tree.live <= baseline.tree.live + 8, 'browser processes grew after warmup');
    assert.ok(current.tree.fds <= baseline.tree.fds + 128, 'browser FDs grew after warmup');
    assert.ok(current.tree.zombies <= baseline.tree.zombies + 8, 'browser zombies grew after warmup');
  }
}

export async function waitBrowserCleanup(sample = namespaceResources, timeoutMs = 5000) {
  const deadline = performance.now() + timeoutMs;
  let transientReadErrors = 0;
  for (;;) {
    try {
      const resources = sample();
      if (resources.tree.live === 1) return { resources, transientReadErrors };
    } catch (error) {
      // Dying sandboxed processes can temporarily deny /proc/<pid>/fd before
      // disappearing. Never treat a denied snapshot as zero processes/FDs.
      if (!['EACCES', 'EPERM'].includes(error.code)) throw error;
      transientReadErrors++;
    }
    if (performance.now() >= deadline) throw Object.assign(new Error('browser cleanup observation deadline'), { code: 'BROWSER_CLEANUP_TIMEOUT' });
    await delay(10);
  }
}

export function assertBrowserResult(result, options, kind) {
  assert.equal(result.schema, 1); assert.equal(result.status, 'passed'); assert.equal(result.browser, kind);
  assert.equal(result.seconds, options.seconds); assert.equal(result.concurrency, options.concurrency);
  assert.equal(result.launches, 1); assert.equal(result.warmupWaves, 3); assert.ok(result.waves > 0);
  assert.equal(result.cleanupFailed ?? false, false); assert.ok(typeof result.version === 'string' && result.version.length > 0);
  assert.ok(result.measuredMs >= options.seconds * 1000); assert.ok(result.samples.length >= 2);
  const waves = result.waves + 3, totals = result.totals;
  assert.equal(totals.echoes, waves * options.concurrency);
  assert.equal(totals.echoBytes, totals.echoes * 65536);
  assert.equal(totals.aborted, waves * Math.floor(options.concurrency / 2));
  assert.equal(totals.heldCompleted + totals.aborted, waves * options.concurrency);
  assert.equal(totals.drains, waves + 1); assert.equal(totals.connections, waves + 1);
  assert.equal(totals.clientHellos, 3 * totals.connections);
  for (const sample of result.samples) assertBrowserResources(sample.resources, result.baseline);
  assertIdle(result.final.lab, result.final.proxy);
  assert.equal(result.final.resources.tree.live, 1, 'browser process survived cleanup');
  assert.equal(result.final.resources.worker.active.Timeout ?? 0, 0);
  assert.equal(result.final.resources.worker.active.TCPSocketWrap ?? 0, 0);
  assert.equal(result.final.resources.worker.active.TCPServerWrap ?? 0, 0);
  assert.equal(result.final.resources.worker.active.ProcessWrap ?? 0, 0);
}
