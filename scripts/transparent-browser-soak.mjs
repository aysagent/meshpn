#!/usr/bin/env node
/** Bounded real-browser soak, supervised outside a private NET/MOUNT/PID namespace. */
import { mkdtemp, mkdir, open, readlink, rm } from 'node:fs/promises';
import { tmpdir, release } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { child } from './lib/browser-lab-driver.mjs';
import { cleanEnvironment, runCommand } from './lib/transparent-acceptance.mjs';
import { browserSoakOptions, namespaceArgs, assertBrowserResult } from './lib/browser-soak.mjs';
import { runBrowserSoak } from './lib/browser-soak-workload.mjs';

const self = fileURLToPath(import.meta.url), root = dirname(dirname(self));
const worker = process.argv[2] === '--isolated';
const options = browserSoakOptions(process.argv.slice(worker ? 3 : 2));
if (options.help) {
  console.log(`Usage: node scripts/transparent-browser-soak.mjs [--browser=all|chrome|firefox] [--seconds=1..3600] [--concurrency=2..12] [--report=/new/path.json]
Defaults: both browsers sequentially, 300 measured seconds EACH after three warmup waves, concurrency 4.
One real browser/profile per kind; verified TLS/H2, echo, stream abort, graceful drain and reconnect.
Private loopback + PID namespace; no TUN, global routing, downloads, TLS bypass or profile cloning.
Requires Linux, Node 22+, rootless unshare, ip, mount, OpenSSL 3, certutil and configured browser binaries.
MESHPN_BROWSER_CHROME, MESHPN_BROWSER_FIREFOX, MESHPN_CERTUTIL select existing tools.
Sampled whole-tree RSS/FD/process budgets, not cgroup limits or a proof of no leaks.
No pcap here; independent tshark checks remain in the browser acceptance suite.
Each worker deadline: requested seconds + 90s, then 5s kill grace. Existing reports are never overwritten.`);
} else if (worker) {
  process.umask(0o077); delete process.env.SSLKEYLOGFILE;
  console.log = console.warn = console.error = () => {};
  const send = (event) => process.stdout.write(`${JSON.stringify(event)}\n`);
  const result = await runBrowserSoak(options, process.env.MESHPN_BROWSER_SOAK_DIR, send);
  send({ type: 'result', result }); process.exitCode = result.status === 'passed' ? 0 : 1;
  // Natural exit required. Kernel destroys remaining namespace members when init exits.
} else {
  const path = options.report ? resolve(options.report) : join(await mkdtemp(join(tmpdir(), 'meshpn-browser-soak-report-')), 'report.json');
  const file = await open(path, 'wx', 0o600);
  const report = { schema: 1, status: 'failed', requested: options, startedAt: new Date().toISOString(),
    platform: { os: process.platform, arch: process.arch, kernel: release(), node: process.version }, results: [],
    limitations: ['loopback-only', 'sampled-not-cgroup-bounded', 'summed-rss-double-counts-shared-pages',
      'no-independent-pcap-in-soak', 'not-production-certification', 'not-proof-of-no-leaks'] };
  const controller = new AbortController(), abort = () => controller.abort();
  process.once('SIGTERM', abort); process.once('SIGINT', abort);
  let directory;
  console.log(`[browser-soak] ${options.browser}, ${options.seconds}s per browser; report=${path}`);
  try {
    if (process.platform !== 'linux' || Number(process.versions.node.split('.')[0]) < 22) throw new Error('BROWSER_SOAK_PLATFORM');
    const env = cleanEnvironment(process.env);
    const git = await runCommand('git', ['rev-parse', 'HEAD'], { cwd: root, env, signal: controller.signal });
    const dirty = await runCommand('git', ['status', '--porcelain'], { cwd: root, env, signal: controller.signal });
    if (git.code !== 0 || dirty.code !== 0 || git.reason || dirty.reason) throw new Error('BROWSER_SOAK_PROVENANCE');
    report.repository = { revision: git.stdout.trim(), dirty: Boolean(dirty.stdout.trim()) };
    directory = await mkdtemp(join(tmpdir(), 'meshpn-browser-soak-private-'));
    for (const kind of options.browser === 'all' ? ['chrome', 'firefox'] : [options.browser]) {
      if (controller.signal.aborted) break;
      const caseDir = join(directory, kind); await mkdir(caseDir, { mode: 0o700 });
      const proc = child('unshare', [...namespaceArgs, 'sh', '-eu', '-c', 'ip link set lo up; exec "$@"', 'browser-soak',
        process.execPath, self, '--isolated', `--browser=${kind}`, `--seconds=${options.seconds}`, `--concurrency=${options.concurrency}`],
      { cwd: root, env: { ...env, MESHPN_BROWSER_SOAK_DIR: caseDir,
        MESHPN_PARENT_NETNS: await readlink('/proc/self/ns/net'), MESHPN_PARENT_PIDNS: await readlink('/proc/self/ns/pid') } });
      const record = { browser: kind, status: 'failed', worker: { closed: false } };
      report.results.push(record);
      let buffer = '', bytes = 0, resultCount = 0, reason, stopping, lastProgress = -30_000, heldLogged = false;
      const stop = (why) => { reason ??= why; stopping ??= proc.stop().catch(() => { reason = 'cleanup-failed'; }); };
      const onAbort = () => stop('aborted');
      controller.signal.addEventListener('abort', onAbort, { once: true });
      const timer = setTimeout(() => stop('deadline'), (options.seconds + 90) * 1000);
      const budget = (chunk) => {
        bytes += Buffer.byteLength(chunk); if (bytes > 4 * 1024 * 1024) { stop('output-limit'); return false; } return true;
      };
      proc.proc.stderr.on('data', budget); // Never persist raw browser/RPC logs or stacks.
      proc.proc.once('error', () => stop('spawn-error'));
      proc.proc.stdout.setEncoding('utf8');
      proc.proc.stdout.on('data', (chunk) => {
        if (!budget(chunk)) return;
        buffer += chunk;
        let end;
        while ((end = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
          try {
            const event = JSON.parse(line);
            if (event.type === 'sample') {
              record.lastSample = event;
              if (event.elapsedMs - lastProgress >= 30_000) {
                lastProgress = event.elapsedMs;
                console.log(`[browser-soak] ${kind} ${Math.round(event.elapsedMs / 1000)}s waves=${event.wave} tree: processes=${event.resources.tree.live} FDs=${event.resources.tree.fds} RSS=${Math.round(event.resources.tree.rss / 1048576)} MiB`);
              }
            } else if (event.type === 'held') {
              if (!heldLogged) { heldLogged = true; console.log(`[browser-soak] ${kind} held requests reached origin`); }
            } else if (event.type === 'result') { resultCount++; record.result = event.result; }
            else stop('unexpected-event');
          } catch { stop('invalid-worker-output'); }
        }
      });
      if (controller.signal.aborted) onAbort();
      const closed = await new Promise((resolve) => proc.proc.once('close', (code, signal) => resolve({ code, signal })));
      clearTimeout(timer); controller.signal.removeEventListener('abort', onAbort); await stopping;
      record.worker = { ...closed, closed: true, reason: reason ?? null };
      try {
        if (reason || closed.code !== 0 || closed.signal || resultCount !== 1 || buffer) throw new Error('BROWSER_SOAK_WORKER');
        assertBrowserResult(record.result, options, kind); record.status = 'passed';
      } catch { record.status = controller.signal.aborted ? 'aborted' : 'failed'; }
      console.log(`[browser-soak] ${kind}: ${record.status}`);
      if (record.status !== 'passed') break;
    }
    report.status = report.results.length === (options.browser === 'all' ? 2 : 1) && report.results.every((item) => item.status === 'passed') ? 'passed' : 'failed';
  } catch (error) { report.error = String(error.code ?? error.message).slice(0, 128); }
  finally {
    if (controller.signal.aborted) report.status = 'aborted';
    try { if (directory) await rm(directory, { recursive: true, force: true }); report.privateFilesRemoved = true; }
    catch { report.status = 'failed'; report.cleanupFailed = true; }
    report.finishedAt = new Date().toISOString();
    try { await file.writeFile(`${JSON.stringify(report, null, 2)}\n`); }
    finally { await file.close(); process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
  }
  console.log(`[browser-soak] ${report.status.toUpperCase()}; report=${path}`);
  process.exitCode = report.status === 'passed' ? 0 : 1;
}
