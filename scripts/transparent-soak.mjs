#!/usr/bin/env node
/** Supervised, time-bounded persistent soak. The worker must exit naturally after cleanup. */
import { mkdtemp, open } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { tmpdir, release } from 'node:os';
import { fileURLToPath } from 'node:url';
import { child } from './lib/browser-lab-driver.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { soakOptions, runSoak } from './lib/transparent-soak.mjs';

const self = fileURLToPath(import.meta.url), root = dirname(dirname(self));
const worker = process.argv[2] === '--worker';
const options = soakOptions(process.argv.slice(worker ? 3 : 2));
if (options.help) {
  console.log(`Usage: node scripts/transparent-soak.mjs [--seconds=1..3600] [--concurrency=2..12] [--report=/new/path.json]
Defaults: 300 measured seconds after three warmup waves, concurrency 4. Linux /proc + Node 22+.
Persistent client/exit/origin; loopback only, no browser, TUN, downloads or global routing changes.
Report contains counts and sampled memory trends, not a proof of no memory leaks or DPI safety.
Existing reports are never overwritten. Parent deadline: requested seconds + 60s, then 5s kill grace.`);
} else if (worker) {
  // Runtime logs are intentionally not persisted. Only our bounded structured events leave this worker.
  console.log = console.warn = console.error = () => {};
  const send = (event) => process.stdout.write(`${JSON.stringify(event)}\n`);
  const controller = new AbortController(), abort = () => controller.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const result = await runSoak(options, { signal: controller.signal, emit: send });
  send({ type: 'result', result });
  process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
  process.exitCode = result.status === 'passed' ? 0 : 1;
  // No process.exit(): leaked referenced timers/sockets must prevent clean exit and fail the supervisor deadline.
} else {
  const path = options.report ? resolve(options.report) : join(await mkdtemp(join(tmpdir(), 'meshpn-soak-')), 'report.json');
  const file = await open(path, 'wx', 0o600);
  const report = { schema: 1, status: 'failed', startedAt: new Date().toISOString(),
    requested: { seconds: options.seconds, concurrency: options.concurrency },
    platform: { os: process.platform, arch: process.arch, kernel: release(), node: process.version, openssl: process.versions.openssl },
    limitations: ['loopback-only', 'node-clients-not-browser-soak', 'sampled-memory-not-leak-proof',
      'not-production-certification', 'no-global-or-cgroup-resource-bound'] };
  const env = cleanEnvironment(process.env), controller = new AbortController();
  const abort = () => controller.abort();
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  console.log(`[soak] ${options.seconds}s after warmup, concurrency=${options.concurrency}; report=${path}`);
  try {
    if (process.platform !== 'linux' || Number(process.versions.node.split('.')[0]) < 22) throw new Error('SOAK_PLATFORM');
    const git = await runCommand('git', ['rev-parse', 'HEAD'], { cwd: root, env, signal: controller.signal });
    const dirty = await runCommand('git', ['status', '--porcelain'], { cwd: root, env, signal: controller.signal });
    if (git.code !== 0 || git.reason || dirty.code !== 0 || dirty.reason) throw new Error('SOAK_PROVENANCE');
    report.repository = { revision: git.stdout.trim(), dirty: Boolean(dirty.stdout.trim()) };
    if (controller.signal.aborted) throw new Error('SOAK_ABORTED');
    const proc = child(process.execPath, [self, '--worker', `--seconds=${options.seconds}`, `--concurrency=${options.concurrency}`], { env, cwd: root });
    report.worker = { pid: proc.proc.pid, closed: false };
    let buffer = '', bytes = 0, resultCount = 0, reason, stopping, lastProgress = -30_000;
    const stop = (why) => { reason ??= why; stopping ??= proc.stop().catch(() => { reason = 'cleanup-failed'; }); };
    const onAbort = () => stop('aborted');
    controller.signal.addEventListener('abort', onAbort, { once: true });
    const deadline = setTimeout(() => stop('deadline'), (options.seconds + 60) * 1000);
    const budget = (data) => {
      bytes += Buffer.byteLength(data);
      if (bytes > 4 * 1024 * 1024) { stop('output-limit'); return false; }
      return true;
    };
    proc.proc.stdout.setEncoding('utf8'); proc.proc.stderr.setEncoding('utf8');
    proc.proc.stderr.on('data', budget); // Never copy exception stacks or raw logs into JSON.
    proc.proc.once('error', () => stop('spawn-error'));
    proc.proc.stdout.on('data', (data) => {
      if (!budget(data)) return;
      buffer += data;
      let end;
      while ((end = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
        try {
          const event = JSON.parse(line);
          if (event.type === 'sample') {
            report.lastSample = event;
            if (event.elapsedMs - lastProgress >= 30_000) {
              lastProgress = event.elapsedMs;
              console.log(`[soak] ${Math.round(event.elapsedMs / 1000)}s, waves=${event.wave}, idle FDs=${event.resources.fds}, RSS=${Math.round(event.resources.memory.rss / 1048576)} MiB`);
            }
          } else if (event.type === 'result') { resultCount++; report.result = event.result; }
          else stop('unexpected-event');
        } catch { stop('invalid-worker-output'); }
      }
    });
    if (controller.signal.aborted) onAbort();
    const closed = await new Promise((resolve) => proc.proc.once('close', (code, signal) => resolve({ code, signal })));
    clearTimeout(deadline); controller.signal.removeEventListener('abort', onAbort); await stopping;
    report.worker = { ...report.worker, ...closed, closed: true, reason: reason ?? null };
    report.status = !reason && closed.code === 0 && !closed.signal && resultCount === 1 && !buffer &&
      report.result?.schema === 1 && report.result.status === 'passed' && report.result.waves > 0 &&
      report.result.measuredMs >= options.seconds * 1000 ? 'passed' : controller.signal.aborted ? 'aborted' : 'failed';
  } catch (error) {
    report.error = String(error.code ?? error.message).slice(0, 128);
  } finally {
    if (controller.signal.aborted) report.status = 'aborted';
    report.finishedAt = new Date().toISOString();
    try { await file.writeFile(`${JSON.stringify(report, null, 2)}\n`); }
    finally { await file.close(); process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort); }
  }
  console.log(`[soak] ${report.status.toUpperCase()}; report=${path}`);
  process.exitCode = report.status === 'passed' ? 0 : 1;
}
